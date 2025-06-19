# Top-level Makefile

BPF_SOURCES := $(wildcard syscall_filter/*Monitor/*.bpf.c)
BPF_OBJS    := $(BPF_SOURCES:.bpf.c=.bpf.o)
BPF_SKELS   := $(BPF_OBJS:.bpf.o=.skel.h)

USER_LOADER := monitor_loader
INCLUDE_DIR := include

CFLAGS      := -O2 -g -std=gnu17 -I$(INCLUDE_DIR)
BPF_CFLAGS  := -O2 -g -std=gnu17 -I$(INCLUDE_DIR) -target bpf
LIBS        := -lbpf -lelf -lz -lrdkafka

.PHONY: all bpf elf skel user_loader clean

all: bpf skel user_loader

# 1) step: 각 .bpf.c → .bpf.o (BPF 전용 오브젝트)
bpf: $(BPF_OBJS)

%.bpf.o: %.bpf.c
	clang $(BPF_CFLAGS) -c $< -o $@

# 3) step: bpftool로 skeleton 헤더 생성
skel: $(MONITOR_SKEL)

%.skel.h: %.bpf.o | $(INCLUDE_DIR)
	@echo "GEN SKEL HDR $@"
	@which bpftool >/dev/null 2>&1 && \
	  bpftool gen skeleton $< > $(INCLUDE_DIR)/$(notdir $@) || \
	  /usr/lib/linux-tools/$(shell uname -r)/bpftool gen	 skeleton $< > $(INCLUDE_DIR)/$(notdir $@)

$(INCLUDE_DIR):
	mkdir -p $@

# 4) 유저 로더 컴파일
user_loader: $(USER_LOADER)

$(USER_LOADER): monitor_loader.c $(BPF_SKEL) $(INCLUDE_DIR)/common_event.h
	@echo "CC USER LOADER $@"
	gcc $(CFLAGS) $< -o $@ $(LIBS)

# 5) clean
clean:
	rm -f $(BPF_OBJS) $(MONITOR_ELF) $(MONITOR_SKEL) $(USER_LOADER)
