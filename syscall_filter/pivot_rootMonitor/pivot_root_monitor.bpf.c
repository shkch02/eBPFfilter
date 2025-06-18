#define __TARGET_ARCH_x86

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common_maps.h"
#include "common_event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";


/*공통헤더에 선언
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
*/

SEC("kprobe/__x64_sys_pivot_root")
int trace_pivot_root(struct pt_regs *ctx) {
    const char *new_root = (const char *)PT_REGS_PARM1(ctx);
    const char *put_old = (const char *)PT_REGS_PARM2(ctx);

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->type = EVT_PIVOT_ROOT;
    e->ts_ns  = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->data.pivot_root.comm, sizeof(e->data.pivot_root.comm));
    bpf_probe_read_user_str(&e->data.pivot_root.new_root, sizeof(e->data.pivot_root.new_root), new_root);
    bpf_probe_read_user_str(&e->data.pivot_root.put_old, sizeof(e->data.pivot_root.put_old), put_old);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
