#define __TARGET_ARCH_x86

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 사용자 데이터 포맷 추출 구조체 (capability 설정 정보 구조체)
struct cap_data_t {
    __u32 effective; //활성화된 권한
    __u32 permitted; // 가능하지만 비활된 권한
    __u32 inheritable; //자식에게 상속되는 권한
};

//유저스페이스로 보낼  이벤트 구조체
struct event_t {
    __u32 pid;
    char comm[16]; //프로세스 명
    struct cap_data_t caps[2]; // index 0: current thread, index 1: bounding set (커널 구현에 따라 해석)
};

struct { //링버퍼 맵 선언
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("kprobe/__x64_sys_capset") //capset 후킹
int trace_capset(struct pt_regs *ctx) {
    void *hdr_ptr = (void *)PT_REGS_PARM1(ctx);
    void *data_ptr = (void *)PT_REGS_PARM2(ctx); // capset()의 두 번째 인자인 capability 데이터의 유저 포인터를 획득

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0); //링버퍼 공간 예약
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32; // 유저스페이스로 전송위한 값 저장
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_probe_read_user(&e->caps[0], sizeof(struct cap_data_t), data_ptr);
    bpf_probe_read_user(&e->caps[1], sizeof(struct cap_data_t), data_ptr + sizeof(struct cap_data_t));

    bpf_ringbuf_submit(e, 0); //링버퍼로 제출
    return 0;
}
