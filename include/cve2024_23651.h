// cve2024_23651.h
#ifndef CVE2024_23651_H
#define CVE2024_23651_H

#include <linux/types.h>

// 이벤트 타입 정의
#define EVT_CVE23651 1

// 이벤트 구조체
struct event_t {
    __u64 timestamp;
    __u32 pid;
    __u32 tgid;
    __u8  stage;     // 1=mount, 2=symlink, 3=openat2
};

// FSM 함수 프로토타입
void fsm_cve2024_23651(const struct event_t *e);

#endif // CVE2024_23651_H
