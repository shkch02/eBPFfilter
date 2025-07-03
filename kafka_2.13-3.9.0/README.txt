###카프카 서버 실행
$bin/kafka-server-start.sh config/kraft/server.properties
컨슈머 실행
$bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic syscall_events --from-beginning


##카프카 서버 띄우고,  monitor_loader실행파일 실행하면 카프카 연결,
로그 볼라면 컨슈머 띄우고 컨테이너 실행시켜보면됨




###노드js 서버 띄웠을시 by  npm run start:dev


카프카 프로듀서 생성
$bin/kafka-console-producer.sh --bootstrap-server localhost:9092 --topic syscall_events


fsm에 필터링되는 메세지 생성
>{"pid":1234,"type":4,"ts_ns":1234567890,"data":{"mount":{"flags":0,"comm":"bash","source":"/tmp","target":"/mnt/cache"}}}
