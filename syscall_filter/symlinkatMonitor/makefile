# syscall_filter/symlinkatMonitor/Makefile

# 공통 include 경로 추가
BPF_INC    := -I../../include
BPF_CFLAGS := -g -O2 -std=gnu17 $(BPF_INC) -target bpf -D__TARGET_ARCH_x86

BPF_SRC   := symlinkat_monitor.bpf.c
BPF_OBJ   := symlinkat_monitor.bpf.o
SKEL_HDR  := ../../include/symlinkat_monitor.skel.h

USER_SRC  := symlinkat_monitor_user.c
USER_BIN  := symlinkat_monitor_user

.PHONY: all clean

all: $(USER_BIN)

# 1) .bpf.c → .bpf.o
$(BPF_OBJ): $(BPF_SRC) ../../include/common_maps.h ../../include/common_event.h
	clang $(BPF_CFLAGS) -c $< -o $@

# 2) 스켈레톤 헤더 생성
# include 디렉터리가 없으면 먼저 만들고
../../include:
	mkdir -p $@

$(SKEL_HDR): $(BPF_OBJ) | ../../include
	@which bpftool > /dev/null && \
	  bpftool gen skeleton $< > $@ || \
	  /usr/lib/linux-tools/$(shell uname -r)/bpftool gen skeleton $< > $@

# 3) 유저 바이너리
$(USER_BIN): $(USER_SRC) $(SKEL_HDR)
	gcc -g -O2 -I../../include -o $@ $< -lbpf -lelf -pthread

clean:
	rm -f $(BPF_OBJ) $(SKEL_HDR) $(USER_BIN)
