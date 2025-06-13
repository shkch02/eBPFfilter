// symlinkat_monitor_user.c

#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>               // libbpf 헤더만 include
#include "symlinkat_monitor.skel.h"   // bpftool로 생성된 스켈레톤

static volatile sig_atomic_t exiting = 0;

// BPF 쪽과 동일한 구조체 정의
struct event_t {
    __u32 pid;
    char comm[16];
    char source[128];
    char target[128];
};

static void handle_signal(int sig) {
    exiting = 1;
}

// 링버퍼 콜백: 이벤트가 들어오면 출력
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event_t *e = data;
    printf("[SYMLINKAT] PID=%-6u COMM=%-16s OLD=\"%s\" NEW=\"%s\"\n",
           e->pid, e->comm, e->source, e->target);
    return 0;
}

int main(int argc, char **argv) {
    struct symlinkat_monitor_bpf *skel;
    struct ring_buffer *rb;
    int err;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // 1) 스켈레톤 오픈 & 로드
    skel = symlinkat_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 2) kprobe 어태치
    err = symlinkat_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    // 3) 링버퍼 생성: libbpf.h 안에서 bpf_ringbuf API가 포함되어 있다
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Listening for symlinkat() syscalls...\n");
    // 4) 이벤트 폴링 루프
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
    symlinkat_monitor_bpf__destroy(skel);
    return err != 0;
}
