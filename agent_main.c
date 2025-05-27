// agent_main.c
#include <stdio.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "cve2024_23651.skel.h"
#include "cve2024_23651.h"

static volatile bool exiting = false;
static void sig_handler(int sig) { exiting = true; }

static void handle_event(void *ctx, int cpu, void *data, size_t sz) {
    const struct event_t *e = data;
    if (e->stage == 3)  // 최종 단계 이벤트만 FSM 호출
        fsm_cve2024_23651(e);
}

int main(int argc, char **argv) {
    struct cve2024_23651 *skel = NULL;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 1) eBPF 스켈레톤 로드
    skel = cve2024_23651__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 2) attach
    err = cve2024_23651__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    // 3) perf buffer
    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events), handle_event, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    // 4) 이벤트 루프
    while (!exiting) {
        ring_buffer__poll(rb, 100 /*ms*/);
    }

cleanup:
    ring_buffer__free(rb);
    cve2024_23651__destroy(skel);
    return err != 0;
}
