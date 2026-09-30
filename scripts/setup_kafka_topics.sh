#!/bin/bash
# Create Kafka topics for SentinelAI

KAFKA_BROKER="localhost:9092"

topics=(
    "raw_logs:12:3"
    "normalized_logs:12:3"
    "detections:6:3"
    "incidents:3:3"
    "threat_intel:3:3"
    "reports:3:3"
)

for topic_config in "${topics[@]}"; do
    IFS=':' read -r topic partitions replication <<< "$topic_config"
    echo "Creating topic: $topic (partitions=$partitions, replication=$replication)"
    kafka-topics --bootstrap-server $KAFKA_BROKER \
        --create --topic $topic \
        --partitions $partitions \
        --replication-factor $replication \
        --if-not-exists
done

echo "All topics created."
