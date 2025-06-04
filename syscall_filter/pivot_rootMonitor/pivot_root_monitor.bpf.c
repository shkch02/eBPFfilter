#define __TARGET_ARCH_x86

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct event_t {
    __u32 pid;
    char comm[16];
    char new_root[256];
    char put_old[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("kprobe/__x64_sys_pivot_root")
int trace_pivot_root(struct pt_regs *ctx) {
    const char *new_root = (const char *)PT_REGS_PARM1(ctx);
    const char *put_old = (const char *)PT_REGS_PARM2(ctx);

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->new_root, sizeof(e->new_root), new_root);
    bpf_probe_read_user_str(&e->put_old, sizeof(e->put_old), put_old);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
