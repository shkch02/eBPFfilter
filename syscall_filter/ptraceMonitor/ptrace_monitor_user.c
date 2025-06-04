#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "ptrace_monitor.skel.h"

static volatile sig_atomic_t exiting = 0;

struct event_t {
    __u32 pid;
    __u32 target_pid;
    long request;
    char comm[16];
};

#define PTRACE_ATTACH    16
#define PTRACE_PEEKDATA  2
#define PTRACE_POKEDATA  5

void handle_signal(int sig) {
    exiting = 1;
}

static const char* req_to_str(long req) {
    switch (req) {
        case PTRACE_ATTACH: return "PTRACE_ATTACH";
        case PTRACE_PEEKDATA: return "PTRACE_PEEKDATA";
        case PTRACE_POKEDATA: return "PTRACE_POKEDATA";
        default: return "OTHER";
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event_t *e = data;
    const char *req = req_to_str(e->request);

    if (e->request == PTRACE_ATTACH || e->request == PTRACE_POKEDATA) {
        printf("[PTRACE 🚨] PID=%d COMM=%s tried %s on PID=%d\n",
               e->pid, e->comm, req, e->target_pid);
    } else {
        printf("[PTRACE] PID=%d COMM=%s tried %s on PID=%d\n",
               e->pid, e->comm, req, e->target_pid);
    }

    return 0;
}

int main() {
    struct ptrace_monitor_bpf *skel;
    struct ring_buffer *rb;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skel = ptrace_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to load BPF skeleton\n");
        return 1;
    }

    if (ptrace_monitor_bpf__attach(skel)) {
        fprintf(stderr, "failed to attach BPF program\n");
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        return 1;
    }

    printf("Listening for ptrace()... Ctrl+C to stop\n");
    while (!exiting)
        ring_buffer__poll(rb, 100);

    ring_buffer__free(rb);
    ptrace_monitor_bpf__destroy(skel);
    return 0;
}
