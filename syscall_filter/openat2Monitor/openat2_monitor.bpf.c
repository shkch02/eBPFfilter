// openat2_monitor.bpf.c
#define __TARGET_ARCH_x86

#include <vmlinux.h>            // BTF 기반 CO-RE 지원 헤더
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 이벤트 전달용 구조체
struct event_t {
    __u32 pid;
    char comm[16];
    char filename[256];
};

// 링버퍼 맵 선언 (max_entries = 16MiB)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// __x64_sys_openat2 kprobe: x86_64 커널에서 openat2 진입 시점 훅
SEC("kprobe/__x64_sys_openat2")
int trace_openat2(struct pt_regs *ctx) {
    // 첫 번째 인자: dfd (int)
    // 두 번째 인자: const char *filename
    // 세 번째 인자: struct open_how *how (생략 가능)
    // 네 번째 인자: size_t size (생략)
    const char *pathname = (const char *)PT_REGS_PARM2(ctx);

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    // 사용자 공간에서 전달된 문자열 복사
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), pathname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
