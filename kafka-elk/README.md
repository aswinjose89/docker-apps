# Kafka With ElasticStack Integration
Kafka is a stream processing platform which process messages in queue between producer and consumer via kafka broker, logstash will create a pipeline to ingest data or message from kafka to elasticsearch then kibana will visualize the data from elasticsearch index.

    Data will communicate in the direction of kafka-->logstash-->Elasticsearch-->kibana

## ✨ Kafka Commands

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
