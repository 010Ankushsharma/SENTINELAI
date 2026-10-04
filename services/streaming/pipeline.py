"""Main streaming pipeline orchestrating all services."""
import asyncio
from shared.utils.logging import get_logger
from shared.schemas.events import RawLogEvent, NormalizedEvent
from .producer import EventProducer
from .consumer import EventConsumer
from ..normalization.normalizer import LogNormalizer
from ..detection.engine import DetectionEngine
from ..investigation.investigator import InvestigationEngine
from ..llm_analyst.analyst import LLMAnalyst
from ..reporting.report_generator import ReportGenerator

logger = get_logger(__name__)


class SentinelPipeline:
    """End-to-end security event processing pipeline.
    
    Flow: Raw Logs → Normalize → Detect → Investigate → LLM Analyze → Report
    Target latency: < 5 seconds
    """

    def __init__(self):
        self.producer = EventProducer()
        self.normalizer = LogNormalizer()
        self.detection_engine = DetectionEngine()
        self.investigator = InvestigationEngine()
        self.llm_analyst = LLMAnalyst()
        self.report_generator = ReportGenerator()

    async def start(self):
        """Start the full pipeline."""
        await self.producer.start()
        await self.detection_engine.initialize()
        
        # Start consumers for each stage
        await asyncio.gather(
            self._run_normalization_stage(),
            self._run_detection_stage(),
            self._run_investigation_stage(),
        )

    async def _run_normalization_stage(self):
        """Consume raw logs, normalize, publish to normalized_logs topic."""
        consumer = EventConsumer(topics=["raw_logs"], group_id="normalization")
        await consumer.start()
        
        logger.info("Normalization stage started")
        async for raw_data in consumer.consume():
            try:
                raw_event = RawLogEvent(**raw_data)
                normalized = self.normalizer.normalize(raw_event)
                await self.producer.publish_normalized(normalized.model_dump())
            except Exception as e:
                logger.error("Normalization error", error=str(e))

    async def _run_detection_stage(self):
        """Consume normalized logs, run detection, publish detections."""
        consumer = EventConsumer(topics=["normalized_logs"], group_id="detection")
        await consumer.start()
        
        logger.info("Detection stage started")
        async for norm_data in consumer.consume():
            try:
                event = NormalizedEvent(**norm_data)
                detections = await self.detection_engine.analyze(event)
                for det in detections:
                    await self.producer.publish_detection(det.model_dump())
            except Exception as e:
                logger.error("Detection error", error=str(e))

    async def _run_investigation_stage(self):
        """Consume detections, investigate, create incidents."""
        from shared.schemas.events import Detection
        
        consumer = EventConsumer(topics=["detections"], group_id="investigation")
        await consumer.start()
        
        detection_buffer: list[Detection] = []
        buffer_timeout = 30  # seconds
        
        logger.info("Investigation stage started")
        async for det_data in consumer.consume():
            try:
                detection = Detection(**det_data)
                detection_buffer.append(detection)
                
                # Process buffer when enough detections accumulate
                if len(detection_buffer) >= 5:
                    incident = await self.investigator.investigate(detection_buffer)
                    if incident:
                        await self.producer.publish_incident(incident.model_dump())
                        
                        # Generate reports
                        tech_report = self.report_generator.generate_technical_report(incident)
                        exec_report = self.report_generator.generate_executive_report(incident)
                        
                        logger.info(
                            "Incident and reports generated",
                            incident_id=incident.incident_id,
                        )
                    detection_buffer.clear()
            except Exception as e:
                logger.error("Investigation error", error=str(e))


async def main():
    pipeline = SentinelPipeline()
    await pipeline.start()


if __name__ == "__main__":
    asyncio.run(main())
