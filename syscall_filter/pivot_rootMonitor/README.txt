runc의 pivot_root호출 감지 구현성공

후킹대상 시스템 콜:__x64_sys_pivot_root

$sudo ./pivot_root_monitor_user

필터링 조건문
 struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    
작동결과
  로그
  [PIVOT_ROOT] PID=161595 COMM=runc:[2:INIT] new_root= put_old=

다른 터미널에서 
sudo unshare --mount bash
sudo mkdir -p /tmp/newroot/{old,proc}
sudo mount --bind /tmp/newroot /tmp/newroot
sudo pivot_root /tmp/newroot /tmp/newroot/old
실행시 못잡긴함, 근데 그 터미널 루트로 변함;

new_root,put_old도 안나오네
