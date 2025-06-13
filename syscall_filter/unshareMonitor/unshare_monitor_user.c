#include <bpf/libbpf.h>
#include <linux/types.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include "unshare_monitor.skel.h"

#define CLONE_NEWNS     0x00020000  /* New mount namespace group */
#define CLONE_NEWUTS    0x04000000  /* New utsname namespace */
#define CLONE_NEWIPC    0x08000000  /* New ipc namespace */
#define CLONE_NEWUSER   0x10000000  /* New user namespace */
#define CLONE_NEWPID    0x20000000  /* New pid namespace */
#define CLONE_NEWNET    0x40000000  /* New network namespace */
#define CLONE_NEWCGROUP 0x02000000  /* New cgroup namespace */


static volatile sig_atomic_t exiting = 0;

struct event_t { //링버퍼 맵을 통해 전달받을 구조체 선언
    __u32 pid;
    __u64 flags;
    char comm[16];
};

void handle_signal(int sig) { //탈출 시그널 선언, ctrl + c 받으면 종료
    exiting = 1;
}

static void print_flags(__u64 flags) { //flag읽어서 네임스페이스 분리요청 출력
    if (flags & CLONE_NEWUSER) printf("CLONE_NEWUSER ");
    if (flags & CLONE_NEWNS)   printf("CLONE_NEWNS ");
    if (flags & CLONE_NEWPID)  printf("CLONE_NEWPID ");
    if (flags & CLONE_NEWNET)  printf("CLONE_NEWNET ");
    printf("(0x%llx)", flags);
}

static int handle_event(void *ctx, void *data, size_t data_sz) { //event_t 구조체 받아서 출력
    struct event_t *e = data;
    printf("[UNSHARE] PID=%d COMM=%s FLAGS=", e->pid, e->comm);
    print_flags(e->flags);
    printf("\n");
    return 0;
}

int main() {
    struct unshare_monitor_bpf *skel;
    struct ring_buffer *rb; //링버퍼 객체 포인터

    signal(SIGINT, handle_signal);  //ctrl+c
    signal(SIGTERM, handle_signal); //종료요청 받으면 exiting 1로 바꾸어 종료

    skel = unshare_monitor_bpf__open_and_load(); //bpf.o 오브젝트 파일 로드
    if (!skel) { 
        fprintf(stderr, "failed to load BPF skeleton\n"); //파일 없으면 오류 출력후 종료
        return 1;
    }

    if (unshare_monitor_bpf__attach(skel)) { //스켈레톤에 포함된 각 BPF프로그램을 커널에 attach
        fprintf(stderr, "failed to attach BPF program\n");
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL); //bpf_map_fd : events링버퍼의 FD
    //handle_event : 이벤트 호출시 콜백함수포인터
    if (!rb) { //실패시 오류문 출력
        fprintf(stderr, "failed to create ring buffer\n");
        return 1;
    }

    printf("Listening for unshare(CLONE_NEW*)... Press Ctrl+C to exit\n");
    while (!exiting)
        ring_buffer__poll(rb, 100); //100ms 단위로 링버퍼 검사

    ring_buffer__free(rb); //자원해제
    unshare_monitor_bpf__destroy(skel); //커널에서 언로드
    return 0;
}
