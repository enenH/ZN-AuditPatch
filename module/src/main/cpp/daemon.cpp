#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <string>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <unordered_set>

#include "process_monitor.h"

static std::string cgroup_root;
static std::unordered_set<pid_t> created_pids;

static bool initialize_cgroup() {
    for (const char *root : {"/sys/fs/cgroup/system", "/sys/fs/cgroup"}) {
        if (access(root, F_OK) == 0) {
            cgroup_root = root;
            break;
        }
    }
    if (cgroup_root.empty()) return false;

    DIR *dir = opendir((cgroup_root + "/uid_0").c_str());
    if (!dir) return false;
    bool found = false;
    while (auto *entry = readdir(dir)) {
        if (strncmp(entry->d_name, "pid_", 4) == 0) {
            found = true;
            break;
        }
    }
    closedir(dir);
    return found;
}

static bool is_root_context(pid_t pid, char *context) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%d", pid);
    auto len = getxattr(path, "security.selinux", context, PATH_MAX - 1);
    if (len < 0) return false;
    context[len] = '\0';
    return strcmp(context, "u:r:su:s0") == 0 ||
           strcmp(context, "u:r:ksu:s0") == 0 ||
           strcmp(context, "u:r:magisk:s0") == 0;
}

static void remove_cgroup(pid_t pid) {
    if (!created_pids.contains(pid)) return;
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/uid_1000/pid_%d", cgroup_root.c_str(), pid);
    if (rmdir(path) == 0 || errno == ENOENT) {
        created_pids.erase(pid);
    }
}

static void update_timestamp(const std::string &path, const timespec &now) {
    timespec stamp = now;
    stamp.tv_nsec += 3000000 + rand() % 2000001;
    if (stamp.tv_nsec >= 1000000000) {
        ++stamp.tv_sec;
        stamp.tv_nsec -= 1000000000;
    }
    timespec times[] = {stamp, stamp};
    utimensat(AT_FDCWD, path.c_str(), times, 0);
}

static void initialize_cgroup_files(const std::string &path) {
    timespec now{};
    clock_gettime(CLOCK_REALTIME, &now);
    DIR *dir = opendir(path.c_str());
    if (!dir) return;
    while (auto *entry = readdir(dir)) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        auto file = path + "/" + entry->d_name;
        chmod(file.c_str(), 0775);
        chown(file.c_str(), 1000, 1000);
        update_timestamp(file, now);
    }
    closedir(dir);
}

static void create_cgroup(pid_t pid) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/uid_1000/pid_%d", cgroup_root.c_str(), pid);
    if (access(path, F_OK) == 0) {
        if (created_pids.contains(pid)) {
            char proc[PATH_MAX];
            snprintf(proc, sizeof(proc), "/proc/%d", pid);
            if (access(proc, F_OK) != 0) remove_cgroup(pid);
        }
        if (access(path, F_OK) == 0) return;
    }
    if (mkdir(path, 0775) != 0) return;
    initialize_cgroup_files(path);
    chown(path, 1000, 1000);
    timespec now{};
    clock_gettime(CLOCK_REALTIME, &now);
    update_timestamp(path, now);
    created_pids.insert(pid);
}

static void scan_processes() {
    DIR *dir = opendir("/proc");
    if (!dir) return;
    while (auto *entry = readdir(dir)) {
        if (entry->d_type != DT_DIR) continue;
        char *end = nullptr;
        long pid = strtol(entry->d_name, &end, 10);
        if (!entry->d_name[0] || *end || pid <= 0) continue;
        char context[PATH_MAX];
        if (is_root_context(static_cast<pid_t>(pid), context)) {
            create_cgroup(static_cast<pid_t>(pid));
        }
    }
    closedir(dir);
}

static void check_process(pid_t pid) {
    char context[PATH_MAX];
    for (int attempt = 0; attempt < 3; ++attempt) {
        if (is_root_context(pid, context)) {
            create_cgroup(pid);
            return;
        }
        if (attempt < 2) usleep(25000);
    }
}

static void on_exec(pid_t pid) {
    if (pid > 0) check_process(pid);
}

static void on_fork(pid_t parent, pid_t child) {
    if (parent <= 0 || child <= 0) return;
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%d/status", child);
    FILE *file = fopen(path, "r");
    if (!file) return;
    char line[256];
    pid_t tgid = 0;
    while (fgets(line, sizeof(line), file)) {
        if (sscanf(line, "Tgid:\t%d", &tgid) == 1) break;
    }
    fclose(file);
    if (tgid != child) return;
    char context[PATH_MAX];
    if (is_root_context(parent, context)) check_process(child);
}

static void on_exit(pid_t pid, pid_t tid) {
    if (pid > 0 && pid == tid) remove_cgroup(pid);
}

int main() {
    srand(time(nullptr));
    if (!initialize_cgroup()) return 1;
    const ProcessCallbacks callbacks{scan_processes, on_exec, on_fork, on_exit};
    monitor_processes(callbacks);
    return 0;
}
