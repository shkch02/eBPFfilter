#include <stdio.h>
#include <bpf/libbpf.h>
#include <librdkafka/rdkafka.h>
#include "common_event.h"

// 개별 skeleton include
#include "clone_monitor.skel.h"
#include "unshare_monitor.skel.h"
#include "capset_monitor.skel.h"
#include "mount_monitor.skel.h"
#include "openat2_monitor.skel.h"
#include "pivot_root_monitor.skel.h"
#include "ptrace_monitor.skel.h"
#include "setns_monitor.skel.h"
#include "symlinkat_monitor.skel.h"

static rd_kafka_t *rk; //카프카 프로듀서 핸들

void init_kafka() { //카프카 초기화 함수
    char err[512]; 
    rd_kafka_conf_t *conf = rd_kafka_conf_new(); //카프카 설정객체 생성
    rd_kafka_conf_set(conf, "bootstrap.servers", "localhost:9092", err, sizeof(err)); //카프카 서버주소 설정
    rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, err, sizeof(err)); 카프카 프로듀서 생성
}

static int on_event(void *ctx, void *data, size_t size) {
    struct event_t *e = data; //커널에서 넘어온 raw데이터 구조체로 캐스팅
    char buf[256]; //카프카로 보낼 JSON 메세지 버퍼
    int len = snprintf(buf, sizeof(buf),
        "{\"type\":%u,\"pid\":%u,\"ts\":%llu}\n",
        e->type, e->pid, e->ts_ns);
    rd_kafka_producev(
        rk,
        RD_KAFKA_V_TOPIC("syscall_events"), //토픽 이름 : syscall_events 
        RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY), //버퍼 복사하여 보관
        RD_KAFKA_V_VALUE(buf, len), //보낼 실제 데이터(메시지 페이로드)
        RD_KAFKA_V_END //가변인자 전달 종료 표시
    );
    return 0;
}

int main() {
    struct ring_buffer *rb; //eBPF 링버퍼 핸들
    int map_fd;

    // 각 BPF skeleton open/load/attach
    struct clone_monitor_bpf *clone_skel = clone_monitor_bpf__open_and_load();
    if (!clone_skel || clone_monitor_bpf__attach(clone_skel)) return 1;

    struct unshare_monitor_bpf *unshare_skel = unshare_monitor_bpf__open_and_load();
    if (!unshare_skel || unshare_monitor_bpf__attach(unshare_skel)) return 1;

    struct capset_monitor_bpf *capset_skel = capset_monitor_bpf__open_and_load();
    if (!capset_skel || capset_monitor_bpf__attach(capset_skel)) return 1;

    struct mount_monitor_bpf *mount_skel = mount_monitor_bpf__open_and_load();
    if (!mount_skel || mount_monitor_bpf__attach(mount_skel)) return 1;

    struct openat2_monitor_bpf *openat2_skel = openat2_monitor_bpf__open_and_load();
    if (!openat2_skel || openat2_monitor_bpf__attach(openat2_skel)) return 1;

    struct pivot_root_monitor_bpf *pivot_skel = pivot_root_monitor_bpf__open_and_load();
    if (!pivot_skel || pivot_root_monitor_bpf__attach(pivot_skel)) return 1;

    struct ptrace_monitor_bpf *ptrace_skel = ptrace_monitor_bpf__open_and_load();
    if (!ptrace_skel || ptrace_monitor_bpf__attach(ptrace_skel)) return 1;

    struct setns_monitor_bpf *setns_skel = setns_monitor_bpf__open_and_load();
    if (!setns_skel || setns_monitor_bpf__attach(setns_skel)) return 1;

    struct symlinkat_monitor_bpf *symlink_skel = symlinkat_monitor_bpf__open_and_load();
    if (!symlink_skel || symlinkat_monitor_bpf__attach(symlink_skel)) return 1;

    // ring buffer는 공통 map 사용한다고 가정
    // 여기서는 clone_monitor의 이벤트 map을 예로 사용
    map_fd = bpf_map__fd(clone_skel->maps.events); //맵파일디스크립터
    rb = ring_buffer__new(map_fd, on_event, NULL, NULL); //링버퍼 핸들생성
    if (!rb) return 1;

    init_kafka(); //카프카 초기화
    printf("Monitoring → Kafka(syscall_events)... Ctrl+C to exit\n");
    while (1)
        ring_buffer__poll(rb, 100);

    // 자원 정리
    ring_buffer__free(rb);
    rd_kafka_flush(rk, 1000);
    rd_kafka_destroy(rk);

    clone_monitor_bpf__destroy(clone_skel);
    unshare_monitor_bpf__destroy(unshare_skel);
    capset_monitor_bpf__destroy(capset_skel);
    mount_monitor_bpf__destroy(mount_skel);
    openat2_monitor_bpf__destroy(openat2_skel);
    pivot_root_monitor_bpf__destroy(pivot_skel);
    ptrace_monitor_bpf__destroy(ptrace_skel);
    setns_monitor_bpf__destroy(setns_skel);
    symlinkat_monitor_bpf__destroy(symlink_skel);

    return 0;
}
