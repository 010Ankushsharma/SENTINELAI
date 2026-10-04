"""Kafka producer for publishing security events."""
import json
from aiokafka import AIOKafkaProducer
from shared.config import get_settings
from shared.utils.logging import get_logger

logger = get_logger(__name__)


class EventProducer:
    def __init__(self):
        self.settings = get_settings()
        self._producer: AIOKafkaProducer | None = None

    async def start(self):
        self._producer = AIOKafkaProducer(
            bootstrap_servers=self.settings.kafka_bootstrap_servers,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
            key_serializer=lambda k: k.encode("utf-8") if k else None,
            acks="all",
            enable_idempotence=True,
            compression_type="gzip",
        )
        await self._producer.start()
        logger.info("Kafka producer started")

    async def stop(self):
        if self._producer:
            await self._producer.stop()
            logger.info("Kafka producer stopped")

    async def publish(self, topic: str, key: str, value: dict):
        if not self._producer:
            raise RuntimeError("Producer not started")
        await self._producer.send_and_wait(topic=topic, key=key, value=value)
        logger.debug("Event published", topic=topic, key=key)

    async def publish_raw_log(self, event: dict):
        await self.publish("raw_logs", event.get("event_id", ""), event)

    async def publish_normalized(self, event: dict):
        await self.publish("normalized_logs", event.get("event_id", ""), event)

    async def publish_detection(self, detection: dict):
        await self.publish("detections", detection.get("detection_id", ""), detection)

    async def publish_incident(self, incident: dict):
        await self.publish("incidents", incident.get("incident_id", ""), incident)
