솔직히 말해서, 지금처럼 서브디렉터리마다 각자 Makefile을 갖고 있고, 동시에 “agent_main.c 에서 스켈레톤 쓰기”까지 지원하려면 유지보수가 상당히 버거워질 거예요. 중복된 빌드 로직, 헤더 복사 스크립트, 각 디렉터리별 설정이 슬슬 꼬이기 시작하겠죠.

아래처럼 단순화·통합하는 걸 권장합니다.

1. 루트 Makefile 하나로 통합
문제점
각 서브디렉터리에 Makefile이 흩어져 있으면

공통 CFLAGS/LDFLAGS 바꿀 때 서브마다 수정

스켈레톤 헤더 생성 경로가 제각각

CI에서 “어느 디렉터리”를 빌드해야 할지 헷갈림

제안
최상위 Makefile 에서

find syscall_filter -name '*.bpf.c' 로 소스 목록 수집

한 번에 .bpf.o → .skel.h → per-monitor test 바이너리 + agent 바이너리 빌드

서브디렉터리 Makefile은 제거하거나 “로컬 실험용” 으로만 두세요.

makefile
복사
편집
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
test_harness.c 안에는 앞서 보여준 ringbuf 콜백 + 간단 sys­call 유발 로직.

_test 바이너리로 sudo ./cloneMonitor_test 이렇게 개별 모니터 검증.
