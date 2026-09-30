"""Unit tests for log normalizer."""
import pytest
from datetime import datetime
from services.normalization.normalizer import LogNormalizer
from shared.schemas.events import RawLogEvent, LogSource, Severity


class TestLogNormalizer:
    def setup_method(self):
        self.normalizer = LogNormalizer()

    def test_normalize_firewall_deny(self):
        raw = RawLogEvent(
            source=LogSource.FIREWALL,
            raw_message="DENY TCP 192.168.1.100:54321 -> 10.0.0.5:445",
            source_ip="192.168.1.100",
            dest_ip="10.0.0.5",
        )
        result = self.normalizer.normalize(raw)
        assert result.category == "network"
        assert result.action == "deny"
        assert result.outcome == "failure"
        assert result.severity == Severity.MEDIUM

    def test_normalize_firewall_allow(self):
        raw = RawLogEvent(
            source=LogSource.FIREWALL,
            raw_message="ALLOW TCP 10.0.0.1:443 -> 8.8.8.8:443",
        )
        result = self.normalizer.normalize(raw)
        assert result.action == "allow"
        assert result.outcome == "success"
        assert result.severity == Severity.INFO

    def test_normalize_endpoint_login(self):
        raw = RawLogEvent(
            source=LogSource.ENDPOINT,
            raw_message="Failed login attempt for user admin",
            user="admin",
            hostname="SERVER-01",
        )
        result = self.normalizer.normalize(raw)
        assert result.category == "authentication"

    def test_normalize_unknown_source(self):
        raw = RawLogEvent(
            source=LogSource.APPLICATION,
            raw_message="Some application log",
        )
        result = self.normalizer.normalize(raw)
        assert result.event_id == raw.event_id
