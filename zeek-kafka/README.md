# Prerequisites
Tested environment details
 | Package | Version |
| ------ | ------ |
| Docker | 20.x.x |
| Docker Compose | 1.29.x |
| Zeek | 6.2 |

# Zeek and Kafka Integration with Docker, librdkafka, and ZeekJS

## Overview

This setup involves using Zeek, an open-source network monitoring tool, to generate logs, which are then sent to Kafka, a distributed streaming platform. The integration leverages Docker containers for ease of deployment and management, while librdkafka, a C library for Apache Kafka, handles the communication between Zeek and Kafka. Additionally, ZeekJS, a JavaScript runtime for Zeek, is included to enable writing Zeek scripts in JavaScript for more flexible and dynamic processing.

## Components

| **Item**     | **Description**                                                                                                                                  |
|--------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| **Nodejs**   | A JavaScript runtime built on Chrome's V8 engine, enabling server-side scripting and building scalable network applications.                     |
| **librdkafka** | A high-performance C library implementing the Apache Kafka protocol, providing a reliable and efficient way to produce and consume Kafka messages. |
| **maxminddb**  | A library used to read MaxMind DB files, which contain geolocation data that can be used to determine the geographic location of IP addresses.    |
| **python3**    | A high-level programming language known for its readability and extensive libraries, widely used in web development, data analysis, and scripting. |
| **ZeekJS**     | A JavaScript-based extension for Zeek, allowing custom scripting and extending Zeek's functionality using JavaScript.                          |
| **Kafka**     | A distributed event streaming platform used for building real-time data pipelines                          |


## Major Plugins Used

Major plugins are

| **Item**                       | **Description**                                                                         |
|-------------------------------|-----------------------------------------------------------------------------------------|
| **file-extraction**            | Extracts files transferred over the network for analysis.                               |
| **add-node-names**             | Adds node names to network traffic logs for easier identification and correlation.      |
| **detect-ransomware-filenames**| Identifies potential ransomware by detecting known malicious file names.               |
| **zeek-httpattacks**           | Detects and logs potential HTTP-based attacks.                                          |
| **zeek-log-all-http-headers**  | Logs all HTTP headers for detailed analysis of web traffic.                             |
| **zeek-long-connections**      | Identifies and logs unusually long network connections.                                 |
| **zeek-sniffpass**             | Detects and logs plaintext passwords transmitted over the network.                      |
| **mitre-attack/bzar**          | Implements detection techniques based on the MITRE ATT&CK framework using BZAR.         |
| **zeek-mac-ages**              | Tracks and logs the age of MAC addresses seen on the network.                           |
| **http-stalling-detector**     | Detects and logs instances of HTTP stalling, which may indicate network issues or attacks.|


## Architecture

The system runs in a distributed environment, allowing Zeek instances, Kafka brokers, and other components to operate on separate remote machines. This setup enhances scalability and flexibility in managing the network monitoring infrastructure.

## Implementation Steps

### Zeek Docker Image Setup

- Create a Docker image for Zeek, including the necessary configurations to send logs to Kafka.
- Include librdkafka and ZeekJS in the Docker image to enable Kafka communication and JavaScript scripting.
- Volume mount the `local.zeek` file from the host machine to the container to allow customizable configurations.

### Kafka Setup

- Deploy Kafka brokers in a distributed manner, either using Docker or directly on the host machines.
- Ensure Kafka is accessible to Zeek instances via the network.

### Configuration

#### Zeek Configuration (Optional)

The main Zeek configuration file, `local.zeek`, is used to customize Zeek's behavior, including logging settings and which scripts to load. Include JavaScript scripts with ZeekJS for dynamic processing capabilities. This file is volume-mounted into the Docker container, allowing changes to be made on the host machine without rebuilding the Docker image.

Example configuration in `local.zeek`:

```zeek

# Configure Kafka output
@load packages/zeek-kafka
redef Kafka::send_all_active_logs = T;
redef Kafka::tag_json = T;
redef Kafka::kafka_conf = table(
    ["metadata.broker.list"] = "localhost:29092"
);

# JavaScript processing using ZeekJS
event zeek_init() {
    # Example: Load a JavaScript file
    ZeekJS::load_script("scripts/example.js");
}
```

### Execution Steps

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

Get zeek docker file at 
```
https://ko-fi.com/s/561a626c0a
```

# ✨ Zeek References

 - [Zeek To Kafka Topic Configurations](https://github.com/SeisoLLC/zeek-kafka)
 - [Kafka Understanding]( https://rmoff.net/2018/08/02/kafka-listeners-explained/)
 - [Geolocation Attributes](https://raw.githubusercontent.com/blacktop/docker-zeek/master/scripts/conn-add-geodata.zeek)
 - [zeek packages](https://packages.zeek.org/)
 - [zeek Metron Docker Image](https://hub.docker.com/r/aswin1906/zeek-metron)
 - [MaxMindDB](https://www.maxmind.com/en/geoip-databases)
