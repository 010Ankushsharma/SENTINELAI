"""Investigation engine for correlating detections and building attack context."""
import asyncio
from datetime import datetime, timedelta
from shared.schemas.events import Detection, Incident, Severity
from shared.utils.logging import get_logger

logger = get_logger(__name__)


class InvestigationEngine:
    """Correlate detections, query graph DB, and build incident context."""

    def __init__(self, es_client=None, neo4j_client=None, threat_intel=None):
        self.es = es_client
        self.neo4j = neo4j_client
        self.threat_intel = threat_intel

    async def investigate(self, detections: list[Detection]) -> Incident | None:
        """Investigate a group of related detections and create an incident."""
        if not detections:
            return None

        # 1. Correlate detections
        correlated = self._correlate_detections(detections)
        
        # 2. Gather context from logs
        context = await self._gather_log_context(correlated)
        
        # 3. Query graph for attack path
        attack_path = await self._query_attack_graph(correlated)
        
        # 4. Enrich with threat intelligence
        intel = await self._enrich_threat_intel(correlated)
        
        # 5. Build timeline
        timeline = self._build_timeline(correlated, context)
        
        # 6. Determine severity and attack type
        max_severity = max(correlated, key=lambda d: self._severity_score(d.severity))
        attack_type = self._classify_attack(correlated)
        
        # 7. Calculate risk score
        risk_score = self._calculate_risk_score(correlated, intel)
        
        # 8. Collect affected assets
        affected_assets = set()
        affected_users = set()
        for d in correlated:
            for indicator_key, indicator_val in d.indicators.items():
                if "ip" in indicator_key.lower():
                    if isinstance(indicator_val, list):
                        affected_assets.update(indicator_val)
                    else:
                        affected_assets.add(str(indicator_val))
                if "user" in indicator_key.lower():
                    affected_users.add(str(indicator_val))

        # 9. Collect MITRE techniques
        mitre = set()
        for d in correlated:
            mitre.update(d.mitre_techniques)

        # 10. Build evidence
        evidence = [d.description for d in correlated]

        incident = Incident(
            title=f"{attack_type} - {max_severity.severity.value.upper()} severity",
            description=f"Automated investigation of {len(correlated)} correlated detections",
            severity=max_severity.severity,
            confidence=sum(d.confidence for d in correlated) / len(correlated),
            attack_type=attack_type,
            detections=[d.detection_id for d in correlated],
            affected_assets=list(affected_assets),
            affected_users=list(affected_users),
            mitre_techniques=list(mitre),
            evidence=evidence,
            timeline=timeline,
            risk_score=risk_score,
        )

        logger.info(
            "Incident created",
            incident_id=incident.incident_id,
            attack_type=attack_type,
            severity=incident.severity.value,
        )
        return incident

    def _correlate_detections(self, detections: list[Detection]) -> list[Detection]:
        """Group related detections by shared indicators."""
        # Simple correlation: all detections in the same time window are correlated
        return detections

    async def _gather_log_context(self, detections: list[Detection]) -> dict:
        """Query Elasticsearch for additional log context."""
        if not self.es:
            return {}
        # Would query ES for related events around the detection timeframe
        return {"additional_logs": []}

    async def _query_attack_graph(self, detections: list[Detection]) -> list:
        """Query Neo4j for attack path reconstruction."""
        if not self.neo4j:
            return []
        # Would traverse graph to find attack paths
        return []

    async def _enrich_threat_intel(self, detections: list[Detection]) -> dict:
        """Enrich detections with threat intelligence."""
        if not self.threat_intel:
            return {}
        return {"matched_iocs": [], "cves": []}

    def _build_timeline(self, detections: list[Detection], context: dict) -> list[dict]:
        """Build chronological attack timeline."""
        timeline = []
        for d in sorted(detections, key=lambda x: x.timestamp):
            timeline.append({
                "timestamp": d.timestamp.isoformat(),
                "event": d.rule_name,
                "description": d.description,
                "severity": d.severity.value,
            })
        return timeline

    def _classify_attack(self, detections: list[Detection]) -> str:
        """Classify the overall attack type based on detections."""
        techniques = set()
        for d in detections:
            techniques.update(d.mitre_techniques)
        
        if "T1110" in techniques:
            return "Credential Attack"
        if "T1003" in techniques:
            return "Credential Dumping"
        if "T1059" in techniques or "T1059.001" in techniques:
            return "Malicious Code Execution"
        if "T1021" in techniques or "T1021.002" in techniques:
            return "Lateral Movement"
        if "T1041" in techniques:
            return "Data Exfiltration"
        if "T1071" in techniques or "T1071.004" in techniques:
            return "Command and Control"
        return "Unknown Attack"

    def _severity_score(self, severity: Severity) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
            severity.value, 0
        )

    def _calculate_risk_score(self, detections: list[Detection], intel: dict) -> float:
        """Calculate risk score 0-100."""
        base_score = sum(self._severity_score(d.severity) * 10 for d in detections)
        confidence_factor = sum(d.confidence for d in detections) / len(detections) / 100
        score = min(100.0, base_score * confidence_factor)
        return round(score, 1)
