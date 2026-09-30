"""Unit tests for detection engine."""
import pytest
from services.detection.rules.sigma_engine import SigmaEngine
from shared.schemas.events import NormalizedEvent, LogSource, Severity
from datetime import datetime


class TestSigmaEngine:
    def setup_method(self):
        self.engine = SigmaEngine()
        self.engine.load_rules()

    def test_detect_suspicious_powershell(self):
        event = NormalizedEvent(
            event_id="test-001",
            timestamp=datetime.utcnow(),
            source=LogSource.ENDPOINT,
            category="process",
            action="process_create",
            outcome="success",
            process_name="powershell.exe",
            process_command="-EncodedCommand SQBuAHYAbwBr",
            raw_message="powershell.exe -EncodedCommand SQBuAHYAbwBr",
        )
        detections = self.engine.match(event)
        assert len(detections) > 0
        assert any("PowerShell" in d.rule_name for d in detections)

    def test_detect_mimikatz(self):
        event = NormalizedEvent(
            event_id="test-002",
            timestamp=datetime.utcnow(),
            source=LogSource.ENDPOINT,
            category="process",
            action="process_create",
            outcome="success",
            process_name="mimikatz.exe",
            raw_message="mimikatz.exe executed",
        )
        detections = self.engine.match(event)
        assert len(detections) > 0
        assert any(d.severity.value == "critical" for d in detections)

    def test_no_detection_benign(self):
        event = NormalizedEvent(
            event_id="test-003",
            timestamp=datetime.utcnow(),
            source=LogSource.ENDPOINT,
            category="process",
            action="process_create",
            outcome="success",
            process_name="notepad.exe",
            raw_message="notepad.exe opened",
        )
        detections = self.engine.match(event)
        assert len(detections) == 0
