#include <bpf/libbpf.h>
#include <linux/types.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include "unshare_monitor.skel.h"

#define CLONE_NEWNS     0x00020000  /* New mount namespace group */
#define CLONE_NEWUTS    0x04000000  /* New utsname namespace */
#define CLONE_NEWIPC    0x08000000  /* New ipc namespace */
#define CLONE_NEWUSER   0x10000000  /* New user namespace */
#define CLONE_NEWPID    0x20000000  /* New pid namespace */
#define CLONE_NEWNET    0x40000000  /* New network namespace */
#define CLONE_NEWCGROUP 0x02000000  /* New cgroup namespace */


static volatile sig_atomic_t exiting = 0;

struct event_t {
    __u32 pid;
    __u64 flags;
    char comm[16];
};

void handle_signal(int sig) {
    exiting = 1;
}

static void print_flags(__u64 flags) {
    if (flags & CLONE_NEWUSER) printf("CLONE_NEWUSER ");
    if (flags & CLONE_NEWNS)   printf("CLONE_NEWNS ");
    if (flags & CLONE_NEWPID)  printf("CLONE_NEWPID ");
    if (flags & CLONE_NEWNET)  printf("CLONE_NEWNET ");
    printf("(0x%llx)", flags);
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event_t *e = data;
    printf("[UNSHARE] PID=%d COMM=%s FLAGS=", e->pid, e->comm);
    print_flags(e->flags);
    printf("\n");
    return 0;
}

int main() {
    struct unshare_monitor_bpf *skel;
    struct ring_buffer *rb;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skel = unshare_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to load BPF skeleton\n");
        return 1;
    }

    if (unshare_monitor_bpf__attach(skel)) {
        fprintf(stderr, "failed to attach BPF program\n");
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        return 1;
    }

    printf("Listening for unshare(CLONE_NEW*)... Press Ctrl+C to exit\n");
    while (!exiting)
        ring_buffer__poll(rb, 100);

    ring_buffer__free(rb);
    unshare_monitor_bpf__destroy(skel);
    return 0;
}
