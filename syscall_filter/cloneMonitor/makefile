BPF_OBJ = clone_monitor.bpf.o
SKEL_HDR = clone_monitor.skel.h
USER_OBJ = clone_monitor_user

all: $(USER_OBJ)

# Step 1: compile BPF and generate skeleton
$(SKEL_HDR): $(BPF_OBJ)
	@which bpftool > /dev/null && bpftool gen skeleton $< > $@ || \
		/usr/lib/linux-tools/$(shell uname -r)/bpftool gen skeleton $< > $@

$(BPF_OBJ): clone_monitor.bpf.c
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c $< -o $@

# Step 2: compile user space
$(USER_OBJ): clone_monitor_user.c $(SKEL_HDR)
	gcc -I. -g -o $@ $< -lbpf -lelf -lz

clean:
	rm -f *.o *.skel.* *.h $(USER_OBJ)
