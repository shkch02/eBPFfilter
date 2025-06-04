BPF_OBJ=unshare_monitor.bpf.o
USER_OBJ=unshare_monitor_user

all: $(BPF_OBJ) $(USER_OBJ)

$(BPF_OBJ): unshare_monitor.bpf.c
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c $< -o $@

$(USER_OBJ): unshare_monitor_user.c
	gcc -I. -g -o $@ $< -lbpf -lelf -lz

clean:
	rm -f *.o *.skel.* $(USER_OBJ)

