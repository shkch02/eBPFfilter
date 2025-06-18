// include/common_event.h
#pragma once
//#include <linux/types.h>

struct cap_data_t {
    __u32 effective;
    __u32 permitted;
    __u32 inheritable;
};

enum event_type {
    EVT_CLONE,
    EVT_UNSHARE,
    EVT_OPENAT2,
    EVT_CAPSET,
    EVT_MOUNT,
    EVT_PIVOT_ROOT,
    EVT_PTRACE,
    EVT_SETNS,
    EVT_SYMLINKAT,
    /* …필요한 타입 추가… */
};

struct event_t {
    __u32 pid;
    __u32 type;     // event_type
    __u64 ts_ns;
    union {
        struct { __u64 flags; char comm[16]; } clone;
        struct { __u64 flags; char comm[16]; } unshare;
        struct { char comm[16]; char filename[256]; } openat2; //얘는 왜 플래그 없는지? 
        struct { __u64 flags; char comm[16]; char source[128]; char target[128]; } mount;
        struct { char comm[16]; char new_root[256]; char put_old[256]; } pivot_root;
        struct { __u32 target_pid; long request; char comm[16]; } ptrace;
        struct { __u32 fd; __u64 nstype; char comm[16]; } setns;
        struct { char comm[16]; char source[128]; char target[128]; } symlinkat;
        struct { char comm[16]; struct cap_data_t caps[2]; } capset;
        /* …필요한 페이로드 추가… */
    } data;
};
