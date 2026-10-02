"""Detection engine combining rule-based, ML, and AI detection."""
import asyncio
from datetime import datetime
from shared.schemas.events import NormalizedEvent, Detection, Severity
from shared.utils.logging import get_logger
from .rules.sigma_engine import SigmaEngine
from .ml.anomaly_detector import AnomalyDetector

logger = get_logger(__name__)


class DetectionEngine:
    """Main detection engine orchestrating all detection methods."""

    def __init__(self):
        self.sigma_engine = SigmaEngine()
        self.anomaly_detector = AnomalyDetector()
        self._event_buffer: list[NormalizedEvent] = []
        self._buffer_size = 1000

    async def initialize(self):
        self.sigma_engine.load_rules()
        await self.anomaly_detector.load_models()
        logger.info("Detection engine initialized")

    async def analyze(self, event: NormalizedEvent) -> list[Detection]:
        """Analyze a normalized event and return any detections."""
        detections = []

        # 1. Rule-based detection (Sigma)
        rule_detections = self.sigma_engine.match(event)
        detections.extend(rule_detections)

        # 2. ML-based anomaly detection
        self._event_buffer.append(event)
        if len(self._event_buffer) >= self._buffer_size:
            anomalies = await self.anomaly_detector.detect(self._event_buffer)
            detections.extend(anomalies)
            self._event_buffer.clear()

        if detections:
            logger.info(
                "Detections generated",
                count=len(detections),
                event_id=event.event_id,
            )

        return detections

    async def analyze_batch(self, events: list[NormalizedEvent]) -> list[Detection]:
        """Analyze a batch of events."""
        all_detections = []
        for event in events:
            dets = await self.analyze(event)
            all_detections.extend(dets)
        return all_detections
