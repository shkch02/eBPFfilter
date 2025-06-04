clone 감지필터 제작 완료

후킹대상 시스템콜:__x64_sys_clone

$sudo ./clone_monitor_user

필터링 조건문
   if (!(flags & (CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET)))
        return 0;
        
           // 필터: "bash" 같은 일반 프로세스는 제외
   if (!(comm[0] == 'r' && comm[1] == 'u' && comm[2] == 'n') && // runc
     !(comm[0] == 'c' && comm[1] == 'o' && comm[2] == 'n') && // conmon
     !(comm[0] == 'c' && comm[1] == 'o' && comm[2] == 'n') && // containerd-shim
     !(comm[0] == 'd' && comm[1] == 'o' && comm[2] == 'c'))   // docker
       return 0;

작동결과
  로그
[CLONE] PID=838 COMM=containerd FLAGS=CLONE_NEWNS CLONE_NEWNET (0xffffa79941b3ff58)
[CLONE] PID=161944 COMM=containerd-shim FLAGS=CLONE_NEWNET (0xffffa79940fcbf58)
[CLONE] PID=161944 COMM=containerd-shim FLAGS=CLONE_NEWNET (0xffffa79940fcbf58)
[CLONE] PID=161944 COMM=containerd-shim FLAGS=CLONE_NEWNET (0xffffa79940fcbf58)
[CLONE] PID=161944 COMM=containerd-shim FLAGS=CLONE_NEWNET (0xffffa79940fcbf58)
[CLONE] PID=161944 COMM=containerd-shim FLAGS=CLONE_NEWNET (0xffffa79941587f58)
[CLONE] PID=161944 COMM=containerd-shim FLAGS=CLONE_NEWNS CLONE_NEWNET (0xffffa79940ffbf58)
[CLONE] PID=161944 COMM=containerd-shim FLAGS=CLONE_NEWNET (0xffffa79941597f58)
[CLONE] PID=161944 COMM=containerd-shim FLAGS=CLONE_NEWNET (0xffffa79941587f58)
[CLONE] PID=161944 COMM=containerd-shim FLAGS=CLONE_NEWNS CLONE_NEWNET (0xffffa799415aff58)
[CLONE] PID=161953 COMM=containerd-shim FLAGS=CLONE_NEWNS CLONE_NEWNET (0xffffa799415b7f58)
[CLONE] PID=161953 COMM=containerd-shim FLAGS=CLONE_NEWNS CLONE_NEWNET (0xffffa799415b7f58)
[CLONE] PID=161953 COMM=containerd-shim FLAGS=CLONE_NEWNS CLONE_NEWNET (0xffffa799415b7f58)
[CLONE] PID=161953 COMM=containerd-shim FLAGS=CLONE_NEWNET (0xffffa79940fcbf58)
[CLONE] PID=161953 COMM=containerd-shim FLAGS=CLONE_NEWNS CLONE_NEWNET (0xffffa799415b7f58)
[CLONE] PID=161953 COMM=containerd-shim FLAGS=CLONE_NEWNET (0xffffa7994159ff58)
[CLONE] PID=161953 COMM=containerd-shim FLAGS=CLONE_NEWNS CLONE_NEWNET (0xffffa799415bff58)
[CLONE] PID=161953 COMM=containerd-shim FLAGS=CLONE_NEWNET (0xffffa79941597f58)
[CLONE] PID=161953 COMM=containerd-shim FLAGS=CLONE_NEWNET (0xffffa799415cff58)
[CLONE] PID=161962 COMM=runc FLAGS=CLONE_NEWNET (0xffffa799415dff58)
[CLONE] PID=161971 COMM=runc:[0:PARENT] FLAGS=CLONE_NEWNET (0xffffa799419cff58)
[CLONE] PID=161972 COMM=runc:[1:CHILD] FLAGS=CLONE_NEWNET (0xffffa79941a07f58)
[CLONE] PID=161953 COMM=containerd-shim FLAGS=CLONE_NEWNET (0xffffa799415cff58)
[CLONE] PID=161953 COMM=containerd-shim FLAGS=CLONE_NEWNET (0xffffa799415cff58)
[CLONE] PID=161953 COMM=containerd-shim FLAGS=CLONE_NEWNET (0xffffa799415d7f58)
[CLONE] PID=161953 COMM=containerd-shim FLAGS=CLONE_NEWNET (0xffffa799415c7f58)
[CLONE] PID=838 COMM=containerd FLAGS=CLONE_NEWNS CLONE_NEWNET (0xffffa79941b3ff58)
[CLONE] PID=162008 COMM=containerd-shim FLAGS=CLONE_NEWNET (0xffffa7994165ff58)
[CLONE] PID=162008 COMM=containerd-shim FLAGS=CLONE_NEWNET (0xffffa7994165ff58)
[CLONE] PID=162008 COMM=containerd-shim FLAGS=CLONE_NEWNET (0xffffa7994165ff58)
[CLONE] PID=162008 COMM=containerd-shim FLAGS=CLONE_NEWNET (0xffffa7994165ff58)
[CLONE] PID=162008 COMM=containerd-shim FLAGS=CLONE_NEWNET (0xffffa799419cff58)
[CLONE] PID=162008 COMM=containerd-shim FLAGS=CLONE_NEWNS CLONE_NEWNET (0xffffa79940febf58)
[CLONE] PID=162008 COMM=containerd-shim FLAGS=CLONE_NEWNS CLONE_NEWNET (0xffffa79940febf58)

