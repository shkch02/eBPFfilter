#define __TARGET_ARCH_x86

#include <vmlinux.h> //   /usr/include에 해당 파일 옮겨야함
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define CLONE_NEWNS     0x00020000
#define CLONE_NEWUTS    0x04000000
#define CLONE_NEWIPC    0x08000000
#define CLONE_NEWUSER   0x10000000
#define CLONE_NEWPID    0x20000000
#define CLONE_NEWNET    0x40000000
#define CLONE_NEWCGROUP 0x02000000

struct event_t {
    __u32 pid;
    __u64 flags;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("kprobe/__x64_sys_clone")  // 또는 kprobe/sys_clone
int handle_clone(struct pt_regs *ctx) {
    struct event_t *e;
    unsigned long flags = PT_REGS_PARM1(ctx);
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    if (!(flags & (CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET)))
        return 0;
        
    // 필터: "bash" 같은 일반 프로세스는 제외
    if (!(comm[0] == 'r' && comm[1] == 'u' && comm[2] == 'n') && // runc
      !(comm[0] == 'c' && comm[1] == 'o' && comm[2] == 'n') && // conmon
      !(comm[0] == 'c' && comm[1] == 'o' && comm[2] == 'n') && // containerd-shim
      !(comm[0] == 'd' && comm[1] == 'o' && comm[2] == 'c'))   // docker
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->flags = flags;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
