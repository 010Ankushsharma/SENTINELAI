"""Sigma rule detection engine."""
import re
import yaml
import os
from pathlib import Path
from shared.schemas.events import NormalizedEvent, Detection, Severity
from shared.utils.logging import get_logger

logger = get_logger(__name__)


class SigmaRule:
    def __init__(self, rule_data: dict):
        self.id = rule_data.get("id", "unknown")
        self.title = rule_data.get("title", "Unknown Rule")
        self.description = rule_data.get("description", "")
        self.severity = rule_data.get("level", "medium")
        self.tags = rule_data.get("tags", [])
        self.detection = rule_data.get("detection", {})
        self.mitre = self._extract_mitre(self.tags)

    def _extract_mitre(self, tags: list) -> list[str]:
        return [t.replace("attack.", "") for t in tags if t.startswith("attack.t")]

    def match(self, event: NormalizedEvent) -> bool:
        """Check if event matches this rule's detection logic."""
        selection = self.detection.get("selection", {})
        for field, pattern in selection.items():
            event_value = self._get_field(event, field)
            if event_value is None:
                return False
            if isinstance(pattern, list):
                if not any(self._match_value(event_value, p) for p in pattern):
                    return False
            else:
                if not self._match_value(event_value, pattern):
                    return False
        return True

    def _get_field(self, event: NormalizedEvent, field: str):
        field_map = {
            "process_name": event.process_name,
            "CommandLine": event.process_command,
            "Image": event.process_name,
            "User": event.user,
            "SourceIP": event.source_ip,
            "DestinationIP": event.dest_ip,
            "action": event.action,
            "category": event.category,
        }
        return field_map.get(field, event.metadata.get(field))

    def _match_value(self, actual: str, pattern) -> bool:
        if actual is None:
            return False
        actual_lower = str(actual).lower()
        pattern_str = str(pattern).lower()
        if "*" in pattern_str:
            regex = pattern_str.replace("*", ".*")
            return bool(re.match(regex, actual_lower))
        return pattern_str in actual_lower


class SigmaEngine:
    def __init__(self, rules_dir: str = "data/sigma_rules"):
        self.rules_dir = rules_dir
        self.rules: list[SigmaRule] = []
        self._builtin_rules = self._get_builtin_rules()

    def load_rules(self):
        """Load Sigma rules from YAML files and built-in rules."""
        self.rules = []
        
        # Load built-in rules
        for rule_data in self._builtin_rules:
            self.rules.append(SigmaRule(rule_data))

        # Load from files
        rules_path = Path(self.rules_dir)
        if rules_path.exists():
            for rule_file in rules_path.glob("*.yml"):
                try:
                    with open(rule_file) as f:
                        rule_data = yaml.safe_load(f)
                    self.rules.append(SigmaRule(rule_data))
                except Exception as e:
                    logger.error("Failed to load rule", file=str(rule_file), error=str(e))

        logger.info("Sigma rules loaded", count=len(self.rules))

    def match(self, event: NormalizedEvent) -> list[Detection]:
        detections = []
        for rule in self.rules:
            if rule.match(event):
                severity_map = {
                    "critical": Severity.CRITICAL,
                    "high": Severity.HIGH,
                    "medium": Severity.MEDIUM,
                    "low": Severity.LOW,
                    "informational": Severity.INFO,
                }
                detections.append(
                    Detection(
                        rule_name=rule.title,
                        rule_id=rule.id,
                        severity=severity_map.get(rule.severity, Severity.MEDIUM),
                        confidence=85.0,
                        description=rule.description,
                        source_events=[event.event_id],
                        mitre_techniques=rule.mitre,
                    )
                )
        return detections

    def _get_builtin_rules(self) -> list[dict]:
        return [
            {
                "id": "SENT-001",
                "title": "Suspicious PowerShell Execution",
                "description": "Detects suspicious PowerShell command execution patterns",
                "level": "high",
                "tags": ["attack.execution", "attack.t1059.001"],
                "detection": {
                    "selection": {
                        "process_name": ["*powershell*", "*pwsh*"],
                        "CommandLine": [
                            "*-enc*", "*-encodedcommand*", "*downloadstring*",
                            "*invoke-expression*", "*iex*", "*bypass*",
                        ],
                    }
                },
            },
            {
                "id": "SENT-002",
                "title": "Brute Force Login Attempt",
                "description": "Multiple failed login attempts detected",
                "level": "high",
                "tags": ["attack.credential_access", "attack.t1110"],
                "detection": {
                    "selection": {
                        "category": "authentication",
                        "action": "*fail*",
                    }
                },
            },
            {
                "id": "SENT-003",
                "title": "Mimikatz Execution Detected",
                "description": "Potential Mimikatz credential dumping tool execution",
                "level": "critical",
                "tags": ["attack.credential_access", "attack.t1003"],
                "detection": {
                    "selection": {
                        "process_name": ["*mimikatz*"],
                    }
                },
            },
            {
                "id": "SENT-004",
                "title": "DNS Tunneling Suspected",
                "description": "Unusually long DNS queries suggesting DNS tunneling",
                "level": "high",
                "tags": ["attack.command_and_control", "attack.t1071.004"],
                "detection": {
                    "selection": {
                        "category": "network",
                        "action": "*dns*",
                    }
                },
            },
            {
                "id": "SENT-005",
                "title": "Lateral Movement via PsExec",
                "description": "PsExec remote execution detected",
                "level": "high",
                "tags": ["attack.lateral_movement", "attack.t1021.002"],
                "detection": {
                    "selection": {
                        "process_name": ["*psexec*"],
                    }
                },
            },
        ]
