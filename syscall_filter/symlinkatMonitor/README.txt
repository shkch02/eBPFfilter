symlinkat감시 구현 성공

후킹대상 시스템 콜:__x64_sys_symlinkat

실행파일 실행
$sudo ./symlinkat_monitor_user

필터링 조건문

없음. 필터링안함

작동 결과
다른 터미널에서 컨테이너 생성시 symlinkat감지함

  로그
  [SYMLINKAT] PID=1288   COMM=dockerd          OLD="" NEW=""
  [SYMLINKAT] PID=1288   COMM=dockerd          OLD="" NEW=""
  [SYMLINKAT] PID=1288   COMM=dockerd          OLD="" NEW=""
  [SYMLINKAT] PID=857    COMM=containerd       OLD="" NEW=""
  [SYMLINKAT] PID=1412204 COMM=runc:[2:INIT]    OLD="" NEW=""
  [SYMLINKAT] PID=1412204 COMM=runc:[2:INIT]    OLD="" NEW=""
  [SYMLINKAT] PID=1412204 COMM=runc:[2:INIT]    OLD="" NEW=""
  [SYMLINKAT] PID=1412204 COMM=runc:[2:INIT]    OLD="" NEW=""
  [SYMLINKAT] PID=1412204 COMM=runc:[2:INIT]    OLD="" NEW=""
  [SYMLINKAT] PID=1412204 COMM=runc:[2:INIT]    OLD="" NEW=""


비고
