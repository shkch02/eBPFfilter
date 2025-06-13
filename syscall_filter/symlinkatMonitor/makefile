# Makefile for symlinkat_monitor

# BPF 소스 & 오브젝트
BPF_SRC := symlinkat_monitor.bpf.c
BPF_OBJ := symlinkat_monitor.bpf.o
SKEL_HDR := symlinkat_monitor.skel.h

# User-space 바이너리
USER_SRC := symlinkat_monitor_user.c
USER_BIN := symlinkat_monitor_user

all: $(USER_BIN)

# 1) BPF 오브젝트 컴파일
$(BPF_OBJ): $(BPF_SRC)
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
	      -c $< -o $@

# 2) Skeleton 헤더 생성
$(SKEL_HDR): $(BPF_OBJ)
	@which bpftool > /dev/null && \
	  bpftool gen skeleton $< > $@ || \
	  /usr/lib/linux-tools/$(shell uname -r)/bpftool gen skeleton $< > $@

# 3) User-space 바이너리 컴파일
$(USER_BIN): $(USER_SRC) $(SKEL_HDR)
	gcc -O2 -g -I. -o $@ $(USER_SRC) \
	    -lbpf -lelf -pthread

clean:
	rm -f $(BPF_OBJ) $(SKEL_HDR) $(USER_BIN)

.PHONY: all clean
