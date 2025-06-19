BPF_OBJ=unshare_monitor.bpf.o
USER_OBJ=unshare_monitor_user

all: $(BPF_OBJ) $(USER_OBJ)

$(BPF_OBJ): unshare_monitor.bpf.c
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c $< -o $@

$(USER_OBJ): unshare_monitor_user.c
	gcc -I. -g -o $@ $< -lbpf -lelf -lz

clean:
	rm -f *.o *.skel.* $(USER_OBJ)

# syscall_filter/unshareMonitor/Makefile

# ── 공통 include 디렉터리 지정 ──
BPF_INC    := -I../../include
BPF_CFLAGS := -g -O2 -std=gnu17 $(BPF_INC) -target bpf -D__TARGET_ARCH_x86

# 1) BPF 소스·오브젝트·스켈레톤 헤더
BPF_SRC   := unshare_monitor.bpf.c
BPF_OBJ   := unshare_monitor.bpf.o
SKEL_HDR  := ../../include/unshare_monitor.skel.h

# 2) 유저 바이너리
USER_SRC  := unshare_monitor_user.c
USER_BIN  := unshare_monitor_user

.PHONY: all clean

all: $(USER_BIN)

# 1) .bpf.c → .bpf.o (common_* 헤더 포함)
$(BPF_OBJ): $(BPF_SRC) ../../include/common_maps.h ../../include/common_event.h
	clang $(BPF_CFLAGS) -c $< -o $@

# 2) include/ 디렉터리 보장
../../include:
	mkdir -p $@

# 3) .bpf.o → 스켈레톤 헤더 생성
$(SKEL_HDR): $(BPF_OBJ) | ../../include
	@which bpftool > /dev/null && \
	  bpftool gen skeleton $< > $@ || \
	  /usr/lib/linux-tools/$(shell uname -r)/bpftool gen skeleton $< > $@

# 4) 유저 바이너리 컴파일 (스켈레톤 + 공통 헤더 포함)
$(USER_BIN): $(USER_SRC) $(SKEL_HDR)
	gcc -g -O2 -I../../include -o $@ $< \
	    -lbpf -lelf -lz -pthread

clean:
	rm -f $(BPF_OBJ) $(SKEL_HDR) $(USER_BIN)
