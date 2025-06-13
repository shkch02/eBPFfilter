#include <bpf/libbpf.h>
#include <linux/types.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include "clone_monitor.skel.h"

static volatile sig_atomic_t exiting = 0;

struct event_t {
    __u32 pid;
    __u64 flags;
    char comm[16];
};

#define CLONE_NEWNS     0x00020000
#define CLONE_NEWUSER   0x10000000
#define CLONE_NEWPID    0x20000000
#define CLONE_NEWNET    0x40000000

void handle_signal(int sig) { //종료시그널
    exiting = 1; 
}

static void print_flags(__u64 flags) { //플래그 결과값 출력
    if (flags & CLONE_NEWUSER) printf("CLONE_NEWUSER ");
    if (flags & CLONE_NEWNS)   printf("CLONE_NEWNS ");
    if (flags & CLONE_NEWPID)  printf("CLONE_NEWPID ");
    if (flags & CLONE_NEWNET)  printf("CLONE_NEWNET ");
    printf("(0x%llx)", flags);
}

static int handle_event(void *ctx, void *data, size_t data_sz) { //링버퍼에서 받은 데이터 포인터 event_t로 해석
    struct event_t *e = data;
    printf("[CLONE] PID=%d COMM=%s FLAGS=", e->pid, e->comm);
    print_flags(e->flags);
    printf("\n");
    return 0;
}

int main() {
    struct clone_monitor_bpf *skel; // 스켈레톤,
    struct ring_buffer *rb;         // 링버퍼 객체 생성

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skel = clone_monitor_bpf__open_and_load(); //바이너리 로드
    if (!skel) { //실패처리
        fprintf(stderr, "failed to load BPF skeleton\n");
        return 1;
    }

    if (clone_monitor_bpf__attach(skel)) {
        fprintf(stderr, "failed to attach BPF program\n");
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        return 1;
    }

    printf("Listening for clone(CLONE_NEW*)... Ctrl+C to exit\n");
    while (!exiting)
        ring_buffer__poll(rb, 100); //100ms마다 링버퍼 이벤트 수신

    ring_buffer__free(rb); 
    clone_monitor_bpf__destroy(skel);
    return 0;
}
