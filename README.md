# All Docker Apps

# Prerequisites
 Tested in Docker Version 20.x.x, Docker Compose version 1.29.x 

# ✨ Kafka Setup
Kafka is a stream processing platform which process messages in queue between producer and consumer via kafka broker

Refer https://rmoff.net/2018/08/02/kafka-listeners-explained/

Docker Compose command
```
    docker-compose -f kafka-compose.yml up
``` 

List kafka topics from the container
```
docker exec -it kafka-cntr bash /bin/kafka-topics --list --bootstrap-server localhost:9092
```

Consume messages from the topic name 'codespotify-topic'
```
docker exec -it kafka-cntr bash /bin/kafka-console-consumer --topic codespotify-topic --from-beginning --bootstrap-server localhost:9092
```

Produce messages via topic name 'codespotify-topic'
```
docker exec -it kafka-cntr bash /bin/kafka-console-producer --topic codespotify-topic --bootstrap-server localhost:9092
```

Create topic if needed, logstash config handle the topic creation hence manual creation not required
```
docker exec -it kafka-cntr bash /bin/kafka-topics --create --topic codespotify-topic --bootstrap-server localhost:9092
```