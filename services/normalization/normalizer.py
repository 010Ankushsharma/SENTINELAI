"""Log normalization to common event schema (ECS-aligned)."""
import re
from datetime import datetime
from shared.schemas.events import RawLogEvent, NormalizedEvent, Severity, LogSource
from shared.utils.logging import get_logger

logger = get_logger(__name__)


class LogNormalizer:
    """Normalize raw logs from various sources into a common schema."""

    def normalize(self, raw: RawLogEvent) -> NormalizedEvent:
        parsers = {
            LogSource.FIREWALL: self._parse_firewall,
            LogSource.ENDPOINT: self._parse_endpoint,
            LogSource.CLOUD: self._parse_cloud,
            LogSource.IDENTITY: self._parse_identity,
            LogSource.NETWORK: self._parse_network,
            LogSource.APPLICATION: self._parse_application,
        }

        parser = parsers.get(raw.source, self._parse_generic)
        try:
            return parser(raw)
        except Exception as e:
            logger.error("Normalization failed", error=str(e), event_id=raw.event_id)
            return self._parse_generic(raw)

    def _parse_firewall(self, raw: RawLogEvent) -> NormalizedEvent:
        msg = raw.raw_message.lower()
        action = "allow" if "allow" in msg or "permit" in msg else "deny"
        outcome = "success" if action == "allow" else "failure"

        # Extract IPs from raw message
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw.raw_message)
        src_ip = ips[0] if len(ips) > 0 else raw.source_ip
        dst_ip = ips[1] if len(ips) > 1 else raw.dest_ip

        return NormalizedEvent(
            event_id=raw.event_id,
            timestamp=raw.timestamp,
            source=raw.source,
            category="network",
            action=action,
            outcome=outcome,
            source_ip=src_ip,
            dest_ip=dst_ip,
            source_port=raw.source_port,
            dest_port=raw.dest_port,
            protocol=raw.protocol,
            user=raw.user,
            hostname=raw.hostname,
            severity=Severity.MEDIUM if action == "deny" else Severity.INFO,
            raw_message=raw.raw_message,
            metadata=raw.metadata,
        )

    def _parse_endpoint(self, raw: RawLogEvent) -> NormalizedEvent:
        msg = raw.raw_message.lower()
        category = "process"
        if "login" in msg or "logon" in msg:
            category = "authentication"
        elif "file" in msg:
            category = "file"

        return NormalizedEvent(
            event_id=raw.event_id,
            timestamp=raw.timestamp,
            source=raw.source,
            category=category,
            action=raw.action or "unknown",
            outcome="success",
            source_ip=raw.source_ip,
            user=raw.user,
            hostname=raw.hostname,
            severity=Severity.INFO,
            raw_message=raw.raw_message,
            metadata=raw.metadata,
        )

    def _parse_cloud(self, raw: RawLogEvent) -> NormalizedEvent:
        return self._parse_generic(raw, category="cloud")

    def _parse_identity(self, raw: RawLogEvent) -> NormalizedEvent:
        return self._parse_generic(raw, category="authentication")

    def _parse_network(self, raw: RawLogEvent) -> NormalizedEvent:
        return self._parse_generic(raw, category="network")

    def _parse_application(self, raw: RawLogEvent) -> NormalizedEvent:
        return self._parse_generic(raw, category="application")

    def _parse_generic(self, raw: RawLogEvent, category: str = "unknown") -> NormalizedEvent:
        return NormalizedEvent(
            event_id=raw.event_id,
            timestamp=raw.timestamp,
            source=raw.source,
            category=category,
            action=raw.action or "unknown",
            outcome="unknown",
            source_ip=raw.source_ip,
            dest_ip=raw.dest_ip,
            user=raw.user,
            hostname=raw.hostname,
            severity=Severity.INFO,
            raw_message=raw.raw_message,
            metadata=raw.metadata,
        )
