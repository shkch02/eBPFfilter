# Top-level Makefile

# 모니터 서브디렉터리 리스트
BPF_DIRS := syscall_filter/cloneMonitor \
            syscall_filter/unshareMonitor \
            syscall_filter/mountMonitor \
            syscall_filter/openat2Monitor \
            syscall_filter/pivot_rootMonitor \
            syscall_filter/ptraceMonitor \
            syscall_filter/setnsMonitor \
            syscall_filter/symlinkatMonitor \
            syscall_filter/capsetMonitor

# 사용자 로더 바이너리 이름
USER_LOADER := monitor_loader

# 공통 인클루드 디렉터리
INCLUDE_DIR := include

CFLAGS := -O2 -g -std=gnu17 -I$(INCLUDE_DIR)
LIBS   := -lbpf -lelf -lz -lrdkafka

.PHONY: all bpf user_loader clean

all: bpf user_loader

# 1) 각 BPF 서브디렉터리에서 Makefile 실행
bpf:
	@for d in $(BPF_DIRS); do \
	  echo "---- building $$d ----"; \
	  $(MAKE) -C $$d; \
	done

# 2) monitor_loader 컴파일
user_loader: $(USER_LOADER)

$(USER_LOADER): monitor_loader.c \
    $(INCLUDE_DIR)/clone_monitor.skel.h \
    $(INCLUDE_DIR)/unshare_monitor.skel.h \
    $(INCLUDE_DIR)/mount_monitor.skel.h \
    $(INCLUDE_DIR)/openat2_monitor.skel.h \
    $(INCLUDE_DIR)/pivot_root_monitor.skel.h \
    $(INCLUDE_DIR)/ptrace_monitor.skel.h \
    $(INCLUDE_DIR)/setns_monitor.skel.h \
    $(INCLUDE_DIR)/symlinkat_monitor.skel.h \
    $(INCLUDE_DIR)/capset_monitor.skel.h \
    $(INCLUDE_DIR)/common_event.h
	@echo "---- building $@ ----"
	gcc $(CFLAGS) $< -o $@ $(LIBS)

# 3) clean: 서브디렉터리와 탑-레벨 둘 다
clean:
	@for d in $(BPF_DIRS); do \
	  echo "---- clean $$d ----"; \
	  $(MAKE) -C $$d clean; \
	done
	@echo "---- clean top-level ----"
	rm -f $(USER_LOADER)
