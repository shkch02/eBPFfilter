setns감시 구현 성공

후킹대상 시스템 콜:__x64_sys_setns

실행파일 실행
$sudo ./setns_monitor_user

필터링 조건문
    // 네임스페이스 관련 요청만 감시
    if (!(nstype & (CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET)))

작동 결과
다른 터미널에서 컨테이너 생성시 딱히 특별한 콤 감지 x 

  로그


비고
탈출 시나리오 작성 필요