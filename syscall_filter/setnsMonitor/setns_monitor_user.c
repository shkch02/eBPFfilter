#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "setns_monitor.skel.h"

static volatile sig_atomic_t exiting = 0;

struct event_t { //구조체 선언
    __u32 pid;
    __u32 fd;
    __u64 nstype;
    char comm[16];
};

#define CLONE_NEWNS     0x00020000
#define CLONE_NEWUSER   0x10000000
#define CLONE_NEWPID    0x20000000
#define CLONE_NEWNET    0x40000000

void handle_signal(int sig) { //종료 시그널
    exiting = 1;
}

static void print_flags(__u64 flags) { //플래그
    if (flags & CLONE_NEWUSER) printf("CLONE_NEWUSER ");
    if (flags & CLONE_NEWNS)   printf("CLONE_NEWNS ");
    if (flags & CLONE_NEWPID)  printf("CLONE_NEWPID ");
    if (flags & CLONE_NEWNET)  printf("CLONE_NEWNET ");
    printf("(0x%llx)", flags);
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event_t *e = data;
    printf("[SETNS] PID=%d COMM=%s FD=%d NSTYPE=", e->pid, e->comm, e->fd);
    print_flags(e->nstype);
    printf("\n");
    return 0;
}

int main() {
    struct setns_monitor_bpf *skel;
    struct ring_buffer *rb;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skel = setns_monitor_bpf__open_and_load(); //바이너리 파일 로드
    if (!skel) {
        fprintf(stderr, "failed to load skeleton\n");
        return 1;
    }

    if (setns_monitor_bpf__attach(skel)) {
        fprintf(stderr, "failed to attach BPF program\n");
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        return 1;
    }

    printf("Listening for setns() calls with CLONE_NEW*... Ctrl+C to stop\n");
    while (!exiting)
        ring_buffer__poll(rb, 100);

    ring_buffer__free(rb);
    setns_monitor_bpf__destroy(skel);
    return 0;
}
