// cve2024_23651.c
#include "cve2024_23651.h"
#include <stdio.h>

// 타임맵 키: pid, value: last syscall timestamp
BPF_HASH(ts_map, u32, u64);

// perf 이벤트 출력
BPF_PERF_OUTPUT(events);

int trace_mount(struct tracepoint__syscalls__sys_enter_mount *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    u32 key = pid;
    ts_map.update(&key, &ts);
    struct event_t e = {};
    e.timestamp = ts;
    e.pid = pid;
    e.stage = 1;
    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

int trace_symlinkat(struct tracepoint__syscalls__sys_enter_symlinkat *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 *tsp = ts_map.lookup(&pid);
    if (!tsp) return 0;
    u64 ts = bpf_ktime_get_ns();
    struct event_t e = {};
    e.timestamp = ts;
    e.pid = pid;
    e.stage = 2;
    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

int trace_openat2(struct tracepoint__syscalls__sys_enter_openat2 *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 *tsp = ts_map.lookup(&pid);
    if (!tsp) return 0;
    u64 ts = bpf_ktime_get_ns();
    // race window 1ms = 1e6 ns
    if (ts - *tsp < 1000000) {
        struct event_t e = {};
        e.timestamp = ts;
        e.pid = pid;
        e.stage = 3;
        events.perf_submit(ctx, &e, sizeof(e));
    }
    ts_map.delete(&pid);
    return 0;
}

void fsm_cve2024_23651(const struct event_t *e) {
    static u8 state = 0;
    switch (state) {
    case 0:
        if (e->stage == 1) state = 1;
        break;
    case 1:
        if (e->stage == 2) state = 2;
        else if (e->stage == 1) state = 1; // restart
        break;
    case 2:
        if (e->stage == 3) {
            printf("[CVE-2024-23651] Race detected (pid=%d)\n", e->pid);
            state = 0;
        }
        break;
    }
}
