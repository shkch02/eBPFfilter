#define __TARGET_ARCH_x86

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common_maps.h"
#include "common_event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* 공통헤더로 처리
struct event_t {
    __u32 pid;
    __u64 flags;
    char comm[16];
    char source[128]; //마운트 할 대상
    char target[128]; //마운트 할 위치 
};

struct { //링버퍼 맵 선언
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");
*/
SEC("kprobe/__x64_sys_mount")
int trace_mount(struct pt_regs *ctx) {
    const char *source = (const char *)PT_REGS_PARM1(ctx); //인자 추출
    const char *target = (const char *)PT_REGS_PARM2(ctx);
    unsigned long flags = PT_REGS_PARM4(ctx);

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0); //링버퍼 예약
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32; //정보 입력후
    e->type = EVT_MOUNT;
    e->ts_ns  = bpf_ktime_get_ns(); 
    e->data.mount.flags = flags;
    bpf_get_current_comm(&e->data.mount.comm, sizeof(e->data.mount.comm));
    bpf_probe_read_user_str(&e->data.mount.source, sizeof(e->data.mount.source), source);
    bpf_probe_read_user_str(&e->data.mount.target, sizeof(e->data.mount.target), target);

    bpf_ringbuf_submit(e, 0); //제출
    return 0;
}
