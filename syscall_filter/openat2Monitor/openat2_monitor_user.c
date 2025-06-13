// openat2_monitor_user.c

#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>               // libbpf 헤더만 include
#include "openat2_monitor.skel.h"     // bpftool로 생성된 스켈레톤

static volatile sig_atomic_t exiting = 0;

// BPF 쪽과 동일한 구조체 정의
struct event_t {
    __u32 pid;
    char comm[16];
    char filename[256];
};

static void handle_signal(int sig) {
    exiting = 1;
}

// 링버퍼 콜백: 이벤트가 들어오면 출력
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event_t *e = data;
    printf("[OPENAT2] PID=%-6u COMM=%-16s PATH=\"%s\"\n",
           e->pid, e->comm, e->filename);
    return 0;
}

int main(int argc, char **argv) {
    struct openat2_monitor_bpf *skel;
    struct ring_buffer *rb;
    int err;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // 1) BPF 스켈레톤 로드
    skel = openat2_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 2) kprobe 어태치
    err = openat2_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %d\n", err);
        goto cleanup;
    }

    // 3) 링버퍼 생성 & 콜백 등록
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Listening for openat2() syscalls...\n");
    // 4) 이벤트 루프
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /*ms*/);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    if (rb)
        ring_buffer__free(rb);
    openat2_monitor_bpf__destroy(skel);
    return err != 0;
}
