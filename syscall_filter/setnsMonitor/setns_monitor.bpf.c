#define __TARGET_ARCH_x86

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// CLONE_NEW* 상수 정의
#define CLONE_NEWNS     0x00020000
#define CLONE_NEWUTS    0x04000000
#define CLONE_NEWIPC    0x08000000
#define CLONE_NEWUSER   0x10000000
#define CLONE_NEWPID    0x20000000
#define CLONE_NEWNET    0x40000000
#define CLONE_NEWCGROUP 0x02000000

struct event_t {
    __u32 pid;
    __u32 fd;
    __u64 nstype;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("kprobe/__x64_sys_setns")
int handle_setns(struct pt_regs *ctx) {
    int fd = PT_REGS_PARM1(ctx);
    unsigned long nstype = PT_REGS_PARM2(ctx);

    // 네임스페이스 관련 요청만 감시
    if (!(nstype & (CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET)))
        return 0;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->fd = fd;
    e->nstype = nstype;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
