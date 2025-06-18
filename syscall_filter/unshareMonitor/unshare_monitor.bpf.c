#define __TARGET_ARCH_x86
#define CLONE_NEWNS     0x00020000  /* New mount namespace group */
#define CLONE_NEWUTS    0x04000000  /* New utsname namespace */
#define CLONE_NEWIPC    0x08000000  /* New ipc namespace */
#define CLONE_NEWUSER   0x10000000  /* New user namespace */
#define CLONE_NEWPID    0x20000000  /* New pid namespace */
#define CLONE_NEWNET    0x40000000  /* New network namespace */
#define CLONE_NEWCGROUP 0x02000000  /* New cgroup namespace */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common_maps.h"
#include "common_event.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
struct event_t { //유저스페이스로 넘길 구조체 선언
    __u32 pid;
    __u64 flags;
    char comm[16];
};

struct { //유저스페이스로 데이터 넘길 링버퍼 선언
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

*/
SEC("kprobe/__x64_sys_unshare") //__64_sys_unshare에 후킹, unshare콜 감지
int handle_unshare(struct pt_regs *ctx) {
    struct event_t *e;
    unsigned long flags = PT_REGS_PARM1(ctx); //flag 추출

    if (!(flags & (CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET)))  //필터링 알고리즘 현재는 4가지를 플래그로 가져야 감지됨
        return 0; // 관심 없는 경우 필터링

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0); //버퍼공간 확보
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32; //상위 32는 unshare를 호출한 프로세스의 pid, pid를 e구조체에 저장
    e->type = EVT_UNSHARE;
    e->ts_ns  = bpf_ktime_get_ns();
    e->data.unshare.flags = flags; //플래그저장
    bpf_get_current_comm(&e->data.unshare.comm, sizeof(e->data.unshare.comm)); //프로세스 이름 저장

    bpf_ringbuf_submit(e, 0); //유저스페이스로 구조체 전달
    return 0;
}
