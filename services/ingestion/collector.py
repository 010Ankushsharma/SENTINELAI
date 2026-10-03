"""Log collection from various security sources."""
import asyncio
from datetime import datetime
from typing import AsyncGenerator
from shared.schemas.events import RawLogEvent, LogSource
from shared.utils.logging import get_logger

logger = get_logger(__name__)


class SyslogCollector:
    """Collect logs via syslog (UDP/TCP)."""

    def __init__(self, host: str = "0.0.0.0", port: int = 514):
        self.host = host
        self.port = port

    async def start(self) -> AsyncGenerator[RawLogEvent, None]:
        transport, protocol = await asyncio.get_event_loop().create_datagram_endpoint(
            lambda: SyslogProtocol(),
            local_addr=(self.host, self.port),
        )
        logger.info("Syslog collector started", host=self.host, port=self.port)
        try:
            while True:
                data = await protocol.queue.get()
                yield RawLogEvent(
                    source=LogSource.FIREWALL,
                    raw_message=data.decode("utf-8", errors="replace"),
                    timestamp=datetime.utcnow(),
                )
        finally:
            transport.close()


class SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.queue = asyncio.Queue()

    def datagram_received(self, data, addr):
        self.queue.put_nowait(data)


class FileCollector:
    """Collect logs from files (for testing/batch ingestion)."""

    def __init__(self, file_path: str, source: LogSource):
        self.file_path = file_path
        self.source = source

    async def start(self) -> AsyncGenerator[RawLogEvent, None]:
        import aiofiles
        async with aiofiles.open(self.file_path, "r") as f:
            async for line in f:
                line = line.strip()
                if line:
                    yield RawLogEvent(
                        source=self.source,
                        raw_message=line,
                        timestamp=datetime.utcnow(),
                    )


class APICollector:
    """Collect logs via REST API webhook."""

    @staticmethod
    def parse_webhook(payload: dict) -> RawLogEvent:
        return RawLogEvent(
            source=LogSource(payload.get("source", "application")),
            raw_message=payload.get("message", ""),
            source_ip=payload.get("source_ip"),
            dest_ip=payload.get("dest_ip"),
            user=payload.get("user"),
            hostname=payload.get("hostname"),
            metadata=payload.get("metadata", {}),
        )
