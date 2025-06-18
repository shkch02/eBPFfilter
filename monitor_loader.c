#include <bpf/libbpf.h>
#include <librdkafka/rdkafka.h>
#include "monitor.skel.h"
#include "common_event.h"
#include "clone_monitor.skel.h"
#include "unshare_monitor.skel.h"

static rd_kafka_t *rk;

void init_kafka() {
  char err[512];
  rd_kafka_conf_t *conf = rd_kafka_conf_new();
  rd_kafka_conf_set(conf, "bootstrap.servers", "localhost:9092", err, sizeof(err));
  rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, err, sizeof(err));
}

static int on_event(void *ctx, void *data, size_t size) {
  struct common_event *e = data;
  char buf[256];
  int len = snprintf(buf, sizeof(buf),
    "{\"type\":%u,\"pid\":%u,\"ts\":%llu}\n",
    e->type, e->pid, e->ts_ns);
  rd_kafka_producev(
    rk,
    RD_KAFKA_V_TOPIC("syscall_events"),
    RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
    RD_KAFKA_V_VALUE(buf, len),
    RD_KAFKA_V_END
  );
  return 0;
}

int main() {
  struct monitor_bpf *skel;
  struct ring_buffer *rb;

  init_kafka();

  skel = monitor_bpf__open_and_load();
  if (!skel) return 1;
  if (monitor_bpf__attach(skel)) return 1;

  rb = ring_buffer__new(bpf_map__fd(skel->maps.events_rb),
                        on_event, NULL, NULL);
  if (!rb) return 1;

  printf("Monitoring → Kafka(syscall_events)... Ctrl+C to exit\n");
  while (1)
    ring_buffer__poll(rb, 100);

  ring_buffer__free(rb);
  rd_kafka_flush(rk, 1000);
  rd_kafka_destroy(rk);
  monitor_bpf__destroy(skel);
  return 0;
}
