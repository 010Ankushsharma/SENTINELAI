"""Kafka consumer for processing security events."""
import json
from aiokafka import AIOKafkaConsumer
from shared.config import get_settings
from shared.utils.logging import get_logger

logger = get_logger(__name__)


class EventConsumer:
    def __init__(self, topics: list[str], group_id: str | None = None):
        self.settings = get_settings()
        self.topics = topics
        self.group_id = group_id or self.settings.kafka_group_id
        self._consumer: AIOKafkaConsumer | None = None

    async def start(self):
        self._consumer = AIOKafkaConsumer(
            *self.topics,
            bootstrap_servers=self.settings.kafka_bootstrap_servers,
            group_id=self.group_id,
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            auto_offset_reset="latest",
            enable_auto_commit=True,
        )
        await self._consumer.start()
        logger.info("Kafka consumer started", topics=self.topics)

    async def stop(self):
        if self._consumer:
            await self._consumer.stop()
            logger.info("Kafka consumer stopped")

    async def consume(self):
        """Async generator yielding messages."""
        if not self._consumer:
            raise RuntimeError("Consumer not started")
        async for msg in self._consumer:
            yield msg.value
