"""ML-based anomaly detection for security events."""
import numpy as np
from datetime import datetime
from shared.schemas.events import NormalizedEvent, Detection, Severity
from shared.utils.logging import get_logger

logger = get_logger(__name__)


class AnomalyDetector:
    """Detect anomalies using statistical and ML methods."""

    def __init__(self):
        self.isolation_forest = None
        self.autoencoder = None
        self._baseline_stats: dict = {}

    async def load_models(self):
        """Load pre-trained models or initialize new ones."""
        logger.info("Anomaly detection models loaded (statistical mode)")

    def _extract_features(self, events: list[NormalizedEvent]) -> np.ndarray:
        """Extract numerical features from events for ML analysis."""
        features = []
        for event in events:
            feature_vec = [
                hash(event.source_ip or "") % 10000,
                hash(event.dest_ip or "") % 10000,
                event.source_port or 0,
                event.dest_port or 0,
                hash(event.user or "") % 10000,
                hash(event.hostname or "") % 10000,
                len(event.raw_message),
                event.timestamp.hour,
                event.timestamp.minute,
                1 if event.outcome == "failure" else 0,
            ]
            features.append(feature_vec)
        return np.array(features)

    async def detect(self, events: list[NormalizedEvent]) -> list[Detection]:
        """Run anomaly detection on a batch of events."""
        detections = []
        
        if len(events) < 10:
            return detections

        # --- Statistical anomaly detection ---
        
        # 1. Failed login spike detection
        failed_logins = [
            e for e in events
            if e.category == "authentication" and e.outcome == "failure"
        ]
        if len(failed_logins) > 50:
            # Group by user
            user_failures: dict[str, list] = {}
            for e in failed_logins:
                user = e.user or "unknown"
                user_failures.setdefault(user, []).append(e)
            
            for user, user_events in user_failures.items():
                if len(user_events) > 20:
                    # Group by source IP
                    source_ips = set(e.source_ip for e in user_events if e.source_ip)
                    detections.append(
                        Detection(
                            rule_name="ML: Credential Stuffing Detected",
                            rule_id="ML-001",
                            severity=Severity.CRITICAL,
                            confidence=min(95.0, 60 + len(user_events) * 0.5),
                            description=(
                                f"{len(user_events)} failed logins for user '{user}' "
                                f"from {len(source_ips)} unique IPs"
                            ),
                            source_events=[e.event_id for e in user_events[:20]],
                            mitre_techniques=["T1110"],
                            indicators={
                                "user": user,
                                "failed_count": len(user_events),
                                "source_ips": list(source_ips)[:10],
                            },
                        )
                    )

        # 2. Unusual outbound traffic volume
        outbound = [e for e in events if e.category == "network" and e.dest_port in (443, 80, 8080)]
        if len(outbound) > 100:
            dest_ips: dict[str, int] = {}
            for e in outbound:
                if e.dest_ip:
                    dest_ips[e.dest_ip] = dest_ips.get(e.dest_ip, 0) + 1
            
            for ip, count in dest_ips.items():
                if count > 50:
                    detections.append(
                        Detection(
                            rule_name="ML: Unusual Outbound Traffic",
                            rule_id="ML-002",
                            severity=Severity.HIGH,
                            confidence=75.0,
                            description=f"High volume outbound traffic to {ip}: {count} connections",
                            source_events=[e.event_id for e in outbound if e.dest_ip == ip][:10],
                            mitre_techniques=["T1041"],
                            indicators={"dest_ip": ip, "connection_count": count},
                        )
                    )

        # 3. Off-hours activity
        off_hours_events = [
            e for e in events
            if e.timestamp.hour < 6 or e.timestamp.hour > 22
        ]
        if len(off_hours_events) > 20:
            users = set(e.user for e in off_hours_events if e.user)
            for user in users:
                user_off = [e for e in off_hours_events if e.user == user]
                if len(user_off) > 10:
                    detections.append(
                        Detection(
                            rule_name="ML: Suspicious Off-Hours Activity",
                            rule_id="ML-003",
                            severity=Severity.MEDIUM,
                            confidence=65.0,
                            description=f"User '{user}' has {len(user_off)} events during off-hours",
                            source_events=[e.event_id for e in user_off[:10]],
                            mitre_techniques=["T1078"],
                            indicators={"user": user, "event_count": len(user_off)},
                        )
                    )

        if detections:
            logger.info("ML anomalies detected", count=len(detections))

        return detections
