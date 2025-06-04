#define __TARGET_ARCH_x86

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct event_t {
    __u32 pid;
    __u64 flags;
    char comm[16];
    char source[128];
    char target[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("kprobe/__x64_sys_mount")
int trace_mount(struct pt_regs *ctx) {
    const char *source = (const char *)PT_REGS_PARM1(ctx);
    const char *target = (const char *)PT_REGS_PARM2(ctx);
    unsigned long flags = PT_REGS_PARM4(ctx);

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->flags = flags;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->source, sizeof(e->source), source);
    bpf_probe_read_user_str(&e->target, sizeof(e->target), target);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
