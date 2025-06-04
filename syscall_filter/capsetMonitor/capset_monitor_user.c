#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "capset_monitor.skel.h"

static volatile sig_atomic_t exiting = 0;

struct cap_data_t {
    __u32 effective;
    __u32 permitted;
    __u32 inheritable;
};

struct event_t {
    __u32 pid;
    char comm[16];
    struct cap_data_t caps[2];
};

void handle_signal(int sig) {
    exiting = 1;
}

static void print_caps(const char *label, struct cap_data_t *cap) {
    printf("%s: eff=0x%x perm=0x%x inh=0x%x",
           label, cap->effective, cap->permitted, cap->inheritable);
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event_t *e = data;

    // 간단 필터링: cap_sys_admin은 보통 21번 비트
    if (e->caps[0].effective & (1 << 21) || e->caps[0].permitted & (1 << 21)) {
        printf("[CAPSET 🚨] PID=%d COMM=%s ", e->pid, e->comm);
        print_caps("EFFECTIVE", &e->caps[0]);
        printf("\n");
    } else {
        printf("[CAPSET] PID=%d COMM=%s ", e->pid, e->comm);
        print_caps("EFFECTIVE", &e->caps[0]);
        printf("\n");
    }

    return 0;
}

int main() {
    struct capset_monitor_bpf *skel;
    struct ring_buffer *rb;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skel = capset_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to load BPF skeleton\n");
        return 1;
    }

    if (capset_monitor_bpf__attach(skel)) {
        fprintf(stderr, "failed to attach BPF program\n");
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        return 1;
    }

    printf("Listening for capset()... Ctrl+C to stop\n");
    while (!exiting)
        ring_buffer__poll(rb, 100);

    ring_buffer__free(rb);
    capset_monitor_bpf__destroy(skel);
    return 0;
}
