"""Automated response playbook engine."""
from shared.schemas.events import Incident, Severity
from shared.utils.logging import get_logger

logger = get_logger(__name__)


class PlaybookAction:
    def __init__(self, name: str, description: str, automated: bool = False):
        self.name = name
        self.description = description
        self.automated = automated


class PlaybookEngine:
    """Generate and execute response playbooks based on incident type."""

    def __init__(self):
        self.playbooks = self._load_playbooks()

    def _load_playbooks(self) -> dict:
        return {
            "Credential Attack": [
                PlaybookAction("Reset Passwords", "Force password reset for affected users", False),
                PlaybookAction("Block IPs", "Block source IPs at firewall", True),
                PlaybookAction("Enable MFA", "Enforce MFA for affected accounts", False),
                PlaybookAction("Review Logs", "Check for successful logins from blocked IPs", False),
                PlaybookAction("Notify Users", "Alert affected users of compromise attempt", True),
            ],
            "Credential Dumping": [
                PlaybookAction("Isolate Host", "Network-isolate the affected endpoint", True),
                PlaybookAction("Kill Process", "Terminate malicious process", True),
                PlaybookAction("Reset Credentials", "Reset all credentials on affected host", False),
                PlaybookAction("Forensic Image", "Create forensic disk image", False),
                PlaybookAction("Scan Network", "Scan for lateral movement indicators", True),
            ],
            "Malicious Code Execution": [
                PlaybookAction("Isolate Host", "Network-isolate the affected endpoint", True),
                PlaybookAction("Kill Process", "Terminate malicious process", True),
                PlaybookAction("Collect Artifacts", "Gather malware samples and logs", True),
                PlaybookAction("Scan Similar Hosts", "Check for same IOCs on other hosts", True),
                PlaybookAction("Update Signatures", "Add new signatures to endpoint protection", False),
            ],
            "Lateral Movement": [
                PlaybookAction("Isolate Hosts", "Isolate all affected hosts", True),
                PlaybookAction("Block Credentials", "Disable compromised accounts", True),
                PlaybookAction("Network Segmentation", "Review and tighten network segments", False),
                PlaybookAction("Hunt for Persistence", "Search for persistence mechanisms", False),
            ],
            "Data Exfiltration": [
                PlaybookAction("Block Destination", "Block exfiltration destination", True),
                PlaybookAction("Isolate Source", "Isolate source of data transfer", True),
                PlaybookAction("Assess Data Loss", "Determine what data was exfiltrated", False),
                PlaybookAction("Legal Notification", "Notify legal/compliance team", False),
                PlaybookAction("Preserve Evidence", "Secure all relevant logs and artifacts", True),
            ],
        }

    def get_playbook(self, incident: Incident) -> list[dict]:
        """Get response playbook for an incident."""
        actions = self.playbooks.get(incident.attack_type, [])
        
        if not actions:
            actions = [
                PlaybookAction("Investigate", "Manually investigate the incident", False),
                PlaybookAction("Contain", "Contain affected assets", False),
                PlaybookAction("Notify", "Notify security team lead", True),
            ]

        return [
            {
                "action": a.name,
                "description": a.description,
                "automated": a.automated,
                "priority": i + 1,
            }
            for i, a in enumerate(actions)
        ]
