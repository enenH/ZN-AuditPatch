#pragma once

#include <sys/types.h>

struct ProcessCallbacks {
    void (*on_ready)();
    void (*on_exec)(pid_t pid);
    void (*on_fork)(pid_t parent, pid_t child);
    void (*on_exit)(pid_t pid, pid_t tid);
};

void monitor_processes(const ProcessCallbacks &callbacks);
