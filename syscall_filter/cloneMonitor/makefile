# syscall_filter/cloneMonitor/Makefile

BPF_INC    := -I../../include
BPF_CFLAGS := -g -O2 -std=gnu17 $(BPF_INC) -target bpf -D__TARGET_ARCH_x86

BPF_OBJ    := clone_monitor.bpf.o
SKEL_HDR   := ../../include/clone_monitor.skel.h
USER_OBJ   := clone_monitor_user

.PHONY: all clean

all: $(USER_OBJ)

# --- 1) BPF 오브젝트 컴파일 ---
$(BPF_OBJ): clone_monitor.bpf.c ../../include/common_maps.h ../../include/common_event.h
	clang $(BPF_CFLAGS) -c $< -o $@

# --- 2) 스켈레톤 헤더 생성 ---
$(SKEL_HDR): $(BPF_OBJ) | ../../include
	@which bpftool > /dev/null && \
	  bpftool gen skeleton $< > $@ || \
	  /usr/lib/linux-tools/$(shell uname -r)/bpftool gen skeleton $< > $@

# include 디렉터리 보장
../../include:
	mkdir -p $@

# --- 3) 유저 프로그램 빌드 ---
$(USER_OBJ): clone_monitor_user.c $(SKEL_HDR)
	gcc -I../../include -g -O2 -o $@ $< -lbpf -lelf -lz

# --- clean ---
clean:
	rm -f $(BPF_OBJ) $(SKEL_HDR) $(USER_OBJ)
