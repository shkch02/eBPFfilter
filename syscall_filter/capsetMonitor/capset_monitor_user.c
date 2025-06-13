#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "capset_monitor.skel.h"

static volatile sig_atomic_t exiting = 0; //종료위한 플래그

// 사용자 데이터 포맷 추출 구조체 (capability 설정 정보 구조체)
struct cap_data_t { 
    __u32 effective;
    __u32 permitted;
    __u32 inheritable;
};

struct event_t { //bpf에서 보내온 구조체 by 링버퍼
    __u32 pid;
    char comm[16]; //프로세스명
    struct cap_data_t caps[2];// index 0: current thread, index 1: bounding set (커널 구현에 따라 해석)
};

void handle_signal(int sig) { //종료시그널 ctrl +c등을 받기위한 루프
    exiting = 1;
}

static void print_caps(const char *label, struct cap_data_t *cap) { //label과 cap의 포인터를 인자로 받아 출력함수선언
    printf("%s: eff=0x%x perm=0x%x inh=0x%x",
           label, cap->effective, cap->permitted, cap->inheritable);
}

static int handle_event(void *ctx, void *data, size_t data_sz) { //커널에서 수신한 링버퍼를 event_t로 캐스팅
    struct event_t *e = data; 


    if (e->caps[0].effective & (1 << 21) || e->caps[0].permitted & (1 << 21)) { //21번(cap_sys_admim 요청했는지 검사
        printf("[CAPSET warning] PID=%d COMM=%s ", e->pid, e->comm);
        print_caps("EFFECTIVE", &e->caps[0]);
        printf("\n");
    } else {
        printf("[CAPSET] PID=%d COMM=%s ", e->pid, e->comm);
        print_caps("EFFECTIVE", &e->caps[0]);
        printf("\n");
    }

    return 0;
}

int main() {
    struct capset_monitor_bpf *skel; //스켈레톤,
    struct ring_buffer *rb;          //링버퍼 객체 선언

    signal(SIGINT, handle_signal); 
    signal(SIGTERM, handle_signal); //종료시그널 탐지

    skel = capset_monitor_bpf__open_and_load(); //ebpf 바이너리 로드 및 준비
    if (!skel) { //실패처리
        fprintf(stderr, "failed to load BPF skeleton\n");
        return 1;
    }

    if (capset_monitor_bpf__attach(skel)) {
        fprintf(stderr, "failed to attach BPF program\n");
        return 1;
    }

    //커널과 연결된 링버퍼 생성
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL); 
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        return 1;
    }

    printf("Listening for capset()... Ctrl+C to stop\n");
    while (!exiting)
        ring_buffer__poll(rb, 100);

    ring_buffer__free(rb);
    capset_monitor_bpf__destroy(skel); //종료 및 자원해제
    return 0;
}
