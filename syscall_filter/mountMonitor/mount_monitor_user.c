#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "mount_monitor.skel.h"

static volatile sig_atomic_t exiting = 0;

struct event_t { //커널에서 전송되는 데이터 구조
    __u32 pid;
    __u64 flags;
    char comm[16];
    char source[128];
    char target[128];
};

#define MS_BIND 4096

void handle_signal(int sig) { //종료시그널 탐지용 함수
    exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event_t *e = data;

    // 의심스러운 마운트들 검사
    if ((e->flags & MS_BIND) ||
        strncmp(e->target, "/host", 5) == 0 ||
        strncmp(e->target, "/mnt", 4) == 0 ||
        strncmp(e->target, "/proc", 5) == 0 ||
        strncmp(e->target, "/sys", 4) == 0) {
        printf("[MOUNT warning] PID=%d COMM=%s SOURCE=%s TARGET=%s FLAGS=0x%llx\n",
               e->pid, e->comm, e->source, e->target, e->flags);
    } else {
        printf("[MOUNT] PID=%d COMM=%s SOURCE=%s TARGET=%s FLAGS=0x%llx\n",
               e->pid, e->comm, e->source, e->target, e->flags);
    }

    return 0;
}

int main() {
    struct mount_monitor_bpf *skel;
    struct ring_buffer *rb;

    signal(SIGINT, handle_signal); //종료처리
    signal(SIGTERM, handle_signal);

    skel = mount_monitor_bpf__open_and_load(); //바이너리 파일 로드
    if (!skel) { //실패처리
        fprintf(stderr, "failed to load BPF skeleton\n");
        return 1;
    }

    if (mount_monitor_bpf__attach(skel)) {
        fprintf(stderr, "failed to attach BPF program\n");
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        return 1;
    }

    printf("Listening for mount() syscalls...\n");
    while (!exiting)
        ring_buffer__poll(rb, 100);

    ring_buffer__free(rb);
    mount_monitor_bpf__destroy(skel);
    return 0;
}
