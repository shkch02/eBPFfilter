BPF_OBJ = mount_monitor.bpf.o
SKEL_HDR = mount_monitor.skel.h
USER_OBJ = mount_monitor_user

all: $(USER_OBJ)

# Step 1: build BPF object and generate skeleton header
$(SKEL_HDR): $(BPF_OBJ)
	@which bpftool > /dev/null && bpftool gen skeleton $< > $@ || \
		/usr/lib/linux-tools/$(shell uname -r)/bpftool gen skeleton $< > $@

$(BPF_OBJ): mount_monitor.bpf.c
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c $< -o $@
	@which bpftool > /dev/null && bpftool gen skeleton $@ > $(SKEL_HDR) || \
		/usr/lib/linux-tools/$(shell uname -r)/bpftool gen skeleton $@ > $(SKEL_HDR)

$(USER_OBJ): mount_monitor_user.c $(SKEL_HDR)
	gcc -I. -g -o $@ $< -lbpf -lelf -lz

clean:
	rm -f *.o *.skel.* *.h $(USER_OBJ)
