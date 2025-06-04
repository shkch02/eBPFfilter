ptrace감시 구현 성공

후킹대상 시스템 콜:__x64_sys_ptrace

실행파일 실행
$sudo ./ptrace_monitor_user

필터링 조건문
if (!e) return 0;

작동 결과
  로그
[PTRACE] PID=1974 COMM=strace tried OTHER on PID=101
[PTRACE] PID=1974 COMM=strace tried OTHER on PID=101
[PTRACE] PID=1974 COMM=strace tried OTHER on PID=101
[PTRACE] PID=1974 COMM=strace tried OTHER on PID=101
[PTRACE] PID=1974 COMM=strace tried OTHER on PID=101
[PTRACE] PID=1974 COMM=strace tried OTHER on PID=101
[PTRACE] PID=1974 COMM=strace tried OTHER on PID=101
[PTRACE] PID=1974 COMM=strace tried OTHER on PID=101


비고
탐지는 구현했으나 필터링 구현 미흡으로 과도한 로그발생중