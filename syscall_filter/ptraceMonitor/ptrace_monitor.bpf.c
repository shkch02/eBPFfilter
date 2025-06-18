#define __TARGET_ARCH_x86

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common_maps.h"
#include "common_event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* 공통헤더에 처리
struct event_t {
    __u32 pid;        // 감시자
    __u32 target_pid; // 대상
    long request;     // PTRACE_XXX
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");
*/

SEC("kprobe/__x64_sys_ptrace")
int trace_ptrace(struct pt_regs *ctx) {
    long request = PT_REGS_PARM1(ctx);
    pid_t target_pid = (pid_t)PT_REGS_PARM2(ctx);

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->type = EVT_PTRACE;
    e->ts_ns  = bpf_ktime_get_ns();
    e->data.ptrace.target_pid = target_pid;
    e->data.ptrace.request = request;
    bpf_get_current_comm(&e->data.ptrace.comm, sizeof(e->data.ptrace.comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
