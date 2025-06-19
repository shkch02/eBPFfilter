# syscall_filter/openat2Monitor/Makefile

# ── 공통 include 디렉터리 지정 ──
BPF_INC    := -I../../include
BPF_CFLAGS := -g -O2 -std=gnu17 $(BPF_INC) -target bpf -D__TARGET_ARCH_x86

# 1) BPF 소스·오브젝트·스켈레톤
BPF_SRC   := openat2_monitor.bpf.c
BPF_OBJ   := openat2_monitor.bpf.o
SKEL_HDR  := ../../include/openat2_monitor.skel.h

# 2) User-space 바이너리
USER_SRC  := openat2_monitor_user.c
USER_BIN  := openat2_monitor_user

.PHONY: all clean

all: $(USER_BIN)

# 1) .bpf.c → .bpf.o
#    common_maps.h/common_event.h 은 최상위 include 에서 찾음
$(BPF_OBJ): $(BPF_SRC) ../../include/common_maps.h ../../include/common_event.h
	clang $(BPF_CFLAGS) -c $< -o $@

# 2) .bpf.o → 스켈레톤 헤더
$(SKEL_HDR): $(BPF_OBJ) | ../../include
	@which bpftool > /dev/null && \
	  bpftool gen skeleton $< > $@ || \
	  /usr/lib/linux-tools/$(shell uname -r)/bpftool gen skeleton $< > $@

# include 디렉터리 보장
../../include:
	mkdir -p $@

# 3) 유저 바이너리 컴파일
#    -I../../include 로 common_event.h 와 스켈레톤 헤더 참조
$(USER_BIN): $(USER_SRC) $(SKEL_HDR)
	gcc -g -O2 -I../../include -o $@ $< \
	    -lbpf -lelf -pthread

clean:
	rm -f $(BPF_OBJ) $(SKEL_HDR) $(USER_BIN)
