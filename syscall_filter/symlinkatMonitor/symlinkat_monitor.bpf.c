#define __TARGET_ARCH_x86
#include <vmlinux.h>            // BTF 기반 CO-RE용 헤더
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common_maps.h"
#include "common_event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
// 이벤트 전달용 구조체
struct event_t {
    __u32 pid;
    char comm[16];
    char source[128];
    char target[128];
};

// 링버퍼 맵 선언
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");
*/

// __x64_sys_symlinkat kprobe 함수
SEC("kprobe/__x64_sys_symlinkat")
int trace_symlinkat(struct pt_regs *ctx) {
    // __user 어트리뷰트 없이 일반 포인터로 선언
    const char *source = (const char *)PT_REGS_PARM1(ctx);
    // 두 번째 인자(새 디렉터리 FD)는 쓰지 않으므로 생략
    const char *target = (const char *)PT_REGS_PARM3(ctx);

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->type = EVT_SYMLINKAT;
    e->ts_ns  = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->data.symlinkat.comm, sizeof(e->data.symlinkat.comm));
    // 사용자 공간에서 넘어온 문자열을 안전하게 복사
    bpf_probe_read_user_str(&e->data.symlinkat.source, sizeof(e->data.symlinkat.source), source);
    bpf_probe_read_user_str(&e->data.symlinkat.target, sizeof(e->data.symlinkat.target), target);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
