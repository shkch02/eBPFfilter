unshare감시 구현 성공

후킹대상 시스템 콜:__x64_sys_unshare

실행파일 실행
$sudo ./unshare_monitor_user

필터링 조건문

 if (!(flags & (CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET)))  //필터링 알고리즘 현재는 4가지를 플래그로 가져야 감지됨
        return 0; // 관심 없는 경우 필터링

작동 결과
다른 터미널에서 컨테이너 생성시 unshare감지함

  로그
  [UNSHARE] PID=156019 COMM=runc:[1:CHILD] FLAGS=CLONE_NEWNS CLONE_NEWNET (0xffffa7994263ff58)
  [UNSHARE] PID=156008 COMM=runc FLAGS=CLONE_NEWNET (0xffffa79942617f58)

비고