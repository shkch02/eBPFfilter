# 최상위 Makefile (project root)

BPF_SRCS   := $(shell find syscall_filter -type f -name '*.bpf.c')
BPF_OBJS   := $(BPF_SRCS:.bpf.c=.bpf.o)
SKEL_HDRS  := $(BPF_SRCS:.bpf.c=.skel.h)
TEST_BINS  := $(BPF_SRCS:.bpf.c=_test)

INCLUDE    := include
CFLAGS     := -I$(INCLUDE) -I/usr/include -O2 -g
LDFLAGS    := -lbpf -lelf -lz

all: agent $(TEST_BINS)

# 1) .bpf.c → .bpf.o + 스켈레톤 헤더
%.bpf.o: %.bpf.c
	clang -target bpf $(CFLAGS) -c $< -o $@
	bpftool gen skeleton $@ > $(INCLUDE)/$(notdir $*).skel.h

# 2) per-monitor 테스트 바이너리
%_test: %.bpf.o test_harness.c
	gcc $(CFLAGS) $< $<:.bpf.o=.skel.h test_harness.c -o $@ $(LDFLAGS)

# 3) agent_main + 모든 .bpf.o 링크
agent: agent_main.c $(BPF_OBJS)
	gcc $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f $(BPF_OBJS) $(SKEL_HDRS) $(TEST_BINS) agent
