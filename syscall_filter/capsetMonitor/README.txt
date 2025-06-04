capset()감지 구현 완료

후킹대상 시스템콜:__x64_sys_capset

$sudo ./capset_monitor_user

필터링 조건문
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

작동결과
$sudo capsh --caps="cap_sys_admin+ep" -- -c "bash"

[CAPSET] PID=162205 COMM=sudo EFFECTIVE: eff=0x0 perm=0x0 inh=0x0
[CAPSET] PID=162207 COMM=capsh EFFECTIVE: eff=0x0 perm=0x0 inh=0x0
[CAPSET] PID=162207 COMM=capsh EFFECTIVE: eff=0x0 perm=0x0 inh=0x0



$sudo docker run busybox echo "Hello from BusyBox!"

[CAPSET] PID=162113 COMM=sudo EFFECTIVE: eff=0x0 perm=0x0 inh=0x0
[CAPSET] PID=162151 COMM=runc:[2:INIT] EFFECTIVE: eff=0x0 perm=0x0 inh=0x0


비고
감지하는데, 문제는capsh --caps="cap_sys_admin+ep" -- -c "bash" 실행시  루트로 가있음 ;
