# Prerequisites

 | Package | Version |
| ------ | ------ |
| Docker | 20.x.x |
| Docker Compose | 1.29.x |
| Zeek | 6.2 |

# ✨ Zeek With Kafka Setup
Zeek, formerly known as Bro, is a powerful and flexible network analysis framework that is primarily used for security monitoring. It provides detailed visibility into network traffic and is widely used for network security monitoring, network performance monitoring, and network troubleshooting.

Kafka is a stream processing platform which process messages in queue between producer and consumer via kafka broker

Command to find network interface name
```
nmcli device status or ifconfig
```

Docker Compose command
```
    docker-compose -f zeek-kafka-compose.yml up
``` 

List kafka topics from the container
```
docker exec -it kafka-cntr bash /bin/kafka-topics --list --bootstrap-server localhost:9092
```

Consume messages from the topic name 'zeek'
```
docker exec -it kafka-cntr bash /bin/kafka-console-consumer --topic zeek --from-beginning --bootstrap-server localhost:9092
```

# ✨ Zeek References

 - [Zeek To Kafka Topic Configurations](https://github.com/SeisoLLC/zeek-kafka)
 - [Kafka Understanding]( https://rmoff.net/2018/08/02/kafka-listeners-explained/)
 - [Geolocation Attributes](https://raw.githubusercontent.com/blacktop/docker-zeek/master/scripts/conn-add-geodata.zeek)
 - [zeek packages](https://packages.zeek.org/)