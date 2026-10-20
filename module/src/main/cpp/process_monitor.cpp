#include "process_monitor.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <tuple>
#include <unistd.h>
#include <vector>

enum class EventKind { Exec, Fork, Exit };

static constexpr const char *event_names[] = {
        "sched_process_exec", "sched_process_fork", "sched_process_exit"};
static constexpr const char *trace_roots[] = {
        "/sys/kernel/tracing", "/sys/kernel/debug/tracing"};
static constexpr size_t ring_pages = 128;

struct Event {
    EventKind kind;
    int id = -1;
    int child_pid_offset = -1;
};

struct PerfBuffer {
    int fd;
    int cpu;
    void *mapping;
    perf_event_mmap_page *metadata;
    uint8_t *data;
    size_t size;
    EventKind kind;
    const char *name;
    int child_pid_offset;
};

static bool read_event_id(const char *event, int &id) {
    char path[PATH_MAX];
    for (const char *root : trace_roots) {
        snprintf(path, sizeof(path), "%s/events/sched/%s/id", root, event);
        FILE *file = fopen(path, "r");
        if (!file) continue;
        int count = fscanf(file, "%d", &id);
        fclose(file);
        if (count == 1) return true;
    }
    return false;
}

static bool read_child_pid_offset(int &offset) {
    char path[PATH_MAX];
    const std::string field = std::string("child_pid") + ";";
    for (const char *root : trace_roots) {
        snprintf(path, sizeof(path), "%s/events/sched/%s/format", root, "sched_process_fork");
        FILE *file = fopen(path, "r");
        if (!file) continue;
        char line[512];
        while (fgets(line, sizeof(line), file)) {
            if (!strstr(line, field.c_str())) continue;
            const char *value = strstr(line, "offset:");
            if (value && sscanf(value, "offset:%d", &offset) == 1) {
                fclose(file);
                return true;
            }
        }
        fclose(file);
    }
    return false;
}

static bool copy_ring(const PerfBuffer &buffer, uint64_t tail, void *out, size_t size) {
    if (size > buffer.size) return false;
    const size_t offset = tail & (buffer.size - 1);
    const size_t first = std::min(size, buffer.size - offset);
    memcpy(out, buffer.data + offset, first);
    if (size > first) memcpy(static_cast<uint8_t *>(out) + first, buffer.data, size - first);
    return true;
}

static void dispatch_sample(const PerfBuffer &buffer, const std::vector<uint8_t> &record,
                            const ProcessCallbacks &callbacks) {
    // PERF_SAMPLE_TID followed by PERF_SAMPLE_RAW, after perf_event_header.
    if (record.size() < sizeof(perf_event_header) + 12) return;
    perf_event_header header;
    memcpy(&header, record.data(), sizeof(header));
    if (header.type != PERF_RECORD_SAMPLE) return;
    uint32_t pid, tid, raw_size;
    memcpy(&pid, record.data() + 8, sizeof(pid));
    memcpy(&tid, record.data() + 12, sizeof(tid));
    memcpy(&raw_size, record.data() + 16, sizeof(raw_size));
    if (raw_size > record.size() - 20) return;
    switch (buffer.kind) {
        case EventKind::Exec:
            if (callbacks.on_exec) callbacks.on_exec(static_cast<pid_t>(pid));
            break;
        case EventKind::Fork:
            if (buffer.child_pid_offset >= 0 &&
                static_cast<uint32_t>(buffer.child_pid_offset) + sizeof(pid_t) <= raw_size &&
                callbacks.on_fork) {
                pid_t child;
                memcpy(&child, record.data() + 20 + buffer.child_pid_offset, sizeof(child));
                callbacks.on_fork(static_cast<pid_t>(pid), child);
            }
            break;
        case EventKind::Exit:
            if (callbacks.on_exit) callbacks.on_exit(static_cast<pid_t>(pid), static_cast<pid_t>(tid));
            break;
    }
}

static void consume_buffer(PerfBuffer &buffer, const ProcessCallbacks &callbacks) {
    const uint64_t head = buffer.metadata->data_head;
    std::atomic_thread_fence(std::memory_order_acquire);
    uint64_t tail = buffer.metadata->data_tail;
    while (tail < head) {
        perf_event_header header{};
        if (!copy_ring(buffer, tail, &header, sizeof(header)) ||
            header.size < sizeof(header) || header.size > buffer.size) break;
        std::vector<uint8_t> record(header.size);
        copy_ring(buffer, tail, record.data(), record.size());
        dispatch_sample(buffer, record, callbacks);
        tail += header.size;
    }
    buffer.metadata->data_tail = tail;
    std::atomic_thread_fence(std::memory_order_seq_cst);
}

void monitor_processes(const ProcessCallbacks &callbacks) {
    const auto page_size = static_cast<size_t>(getpagesize());
    const size_t mapping_size = (ring_pages + 1) * page_size;
    Event events[] = {{EventKind::Exec}, {EventKind::Fork}, {EventKind::Exit}};
    for (auto &event : events) {
        if (!read_event_id(event_names[static_cast<int>(event.kind)], event.id)) return;
    }
    if (!read_child_pid_offset(events[1].child_pid_offset)) return;

    std::vector<PerfBuffer> buffers;
    auto cleanup = [&] {
        for (const auto &buffer : buffers) {
            if (buffer.mapping) munmap(buffer.mapping, mapping_size);
            if (buffer.fd >= 0) close(buffer.fd);
        }
    };
    for (const auto &event : events) {
        const long cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
        if (cpu_count < 1) {
            cleanup();
            return;
        }
        for (int cpu = 0; cpu < cpu_count; ++cpu) {
            perf_event_attr attr{};
            attr.type = PERF_TYPE_TRACEPOINT;
            attr.size = sizeof(attr);
            attr.config = event.id;
            attr.sample_period = 1;
            attr.sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_RAW;
            attr.disabled = 1;
            attr.wakeup_events = 1;
            int fd = static_cast<int>(syscall(__NR_perf_event_open, &attr, -1, cpu, -1, 0));
            if (fd < 0) continue;
            void *mapping = mmap(nullptr, mapping_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (mapping == MAP_FAILED) {
                close(fd);
                continue;
            }
            if (ioctl(fd, PERF_EVENT_IOC_RESET, 0) < 0 || ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
                munmap(mapping, mapping_size);
                close(fd);
                continue;
            }
            buffers.push_back({fd, cpu, mapping, static_cast<perf_event_mmap_page *>(mapping),
                               static_cast<uint8_t *>(mapping) + page_size, ring_pages * page_size,
                               event.kind, event_names[static_cast<int>(event.kind)], event.child_pid_offset});
        }
    }
    if (buffers.empty()) return;
    // The release orders each CPU's buffers by the event-name pointer.
    std::sort(buffers.begin(), buffers.end(), [](const PerfBuffer &a, const PerfBuffer &b) {
        return std::tie(a.cpu, a.name) < std::tie(b.cpu, b.name);
    });
    std::vector<pollfd> descriptors;
    for (const auto &buffer : buffers) descriptors.push_back({buffer.fd, POLLIN, 0});
    if (callbacks.on_ready) callbacks.on_ready();
    while (true) {
        if (poll(descriptors.data(), descriptors.size(), -1) < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (size_t i = 0; i < descriptors.size(); ++i) {
            auto revents = descriptors[i].revents;
            descriptors[i].revents = 0;
            if (revents & (POLLERR | POLLHUP)) break;
            if (revents & POLLIN) consume_buffer(buffers[i], callbacks);
        }
    }
    cleanup();
}
