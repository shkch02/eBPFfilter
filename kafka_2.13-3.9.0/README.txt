카프카 서버 실행
bin/kafka-server-start.sh config/kraft/server.properties
컨슈머 실행
bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic syscall_events --from-beginning


카프카 서버 띄우고,  monitor_loader실행파일 실행하면 카프카 연결,
로그 볼라면 컨슈머 띄우고 컨테이너 실행시켜보면됨
