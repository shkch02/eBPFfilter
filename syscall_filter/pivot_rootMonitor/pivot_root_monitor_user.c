#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "pivot_root_monitor.skel.h"

static volatile sig_atomic_t exiting = 0;

struct event_t {
    __u32 pid;
    char comm[16];
    char new_root[256];
    char put_old[256];
};

void handle_signal(int sig) {
    exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event_t *e = data;

    // 의심 경로 필터링 (간단 예시)
    if (strncmp(e->new_root, "/host", 5) == 0 || strncmp(e->put_old, "/host", 5) == 0 ||
        strncmp(e->new_root, "/mnt", 4) == 0 || strncmp(e->put_old, "/mnt", 4) == 0 ||
        strncmp(e->new_root, "/proc", 5) == 0 || strncmp(e->put_old, "/proc", 5) == 0 ||
        strncmp(e->new_root, "/sys", 4) == 0 || strncmp(e->put_old, "/sys", 4) == 0) {
        printf("[PIVOT_ROOT] 🚨 PID=%d COMM=%s new_root=%s put_old=%s\n",
               e->pid, e->comm, e->new_root, e->put_old);
    } else {
        printf("[PIVOT_ROOT] PID=%d COMM=%s new_root=%s put_old=%s\n",
               e->pid, e->comm, e->new_root, e->put_old);
    }

    return 0;
}

int main() {
    struct pivot_root_monitor_bpf *skel;
    struct ring_buffer *rb;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skel = pivot_root_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to load BPF skeleton\n");
        return 1;
    }

    if (pivot_root_monitor_bpf__attach(skel)) {
        fprintf(stderr, "failed to attach BPF program\n");
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        return 1;
    }

    printf("Listening for pivot_root()... Ctrl+C to exit\n");
    while (!exiting)
        ring_buffer__poll(rb, 100);

    ring_buffer__free(rb);
    pivot_root_monitor_bpf__destroy(skel);
    return 0;
}
