"""LLM-powered security analyst for reasoning and explanation."""
import json
import httpx
from shared.config import get_settings
from shared.schemas.events import Incident, Detection
from shared.utils.logging import get_logger

logger = get_logger(__name__)


class LLMAnalyst:
    """AI security analyst powered by Llama."""

    def __init__(self):
        self.settings = get_settings()
        self.base_url = self.settings.llm_base_url
        self.model = self.settings.llm_model

    async def _call_llm(self, prompt: str, system_prompt: str = None) -> str:
        """Call the LLM via Ollama API."""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": messages,
                    "stream": False,
                    "options": {"temperature": 0.1, "num_predict": 4096},
                },
            )
            response.raise_for_status()
            return response.json()["message"]["content"]

    async def analyze_alert(
        self,
        detection: Detection,
        logs: list[dict] = None,
        threat_intel: list[dict] = None,
        user_history: list[dict] = None,
    ) -> dict:
        """Analyze an alert and provide reasoning."""
        system_prompt = """You are an expert SOC analyst AI. Analyze security alerts and provide:
1. Attack classification
2. Confidence score (0-100)
3. Evidence list
4. MITRE ATT&CK mapping
5. Recommended actions
6. Clear reasoning for your decision

Always respond in valid JSON format with these keys:
- attack_type: string
- severity: string (critical/high/medium/low)
- confidence: number
- is_false_positive: boolean
- evidence: list of strings
- reasoning: list of strings
- mitre_techniques: list of strings
- recommended_actions: list of strings
- root_cause: string
"""

        prompt = f"""Analyze this security alert:

ALERT:
- Rule: {detection.rule_name}
- Severity: {detection.severity.value}
- Description: {detection.description}
- MITRE Techniques: {detection.mitre_techniques}
- Indicators: {json.dumps(detection.indicators, default=str)}

ADDITIONAL LOGS:
{json.dumps(logs[:10] if logs else [], default=str, indent=2)}

THREAT INTELLIGENCE:
{json.dumps(threat_intel[:5] if threat_intel else [], default=str, indent=2)}

USER HISTORY:
{json.dumps(user_history[:5] if user_history else [], default=str, indent=2)}

Provide your analysis in JSON format."""

        try:
            result = await self._call_llm(prompt, system_prompt)
            # Parse JSON from response
            start = result.find("{")
            end = result.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(result[start:end])
            return {"error": "Failed to parse LLM response", "raw": result}
        except Exception as e:
            logger.error("LLM analysis failed", error=str(e))
            return {"error": str(e)}

    async def generate_incident_report(self, incident: Incident) -> dict:
        """Generate technical and executive incident reports."""
        system_prompt = """You are a senior SOC analyst generating incident reports.
Generate both a technical report and an executive summary.

Respond in JSON with keys:
- technical_report: string (detailed markdown report)
- executive_summary: string (concise business-focused summary)
- risk_assessment: string
- business_impact: string
- remediation_steps: list of strings
"""

        prompt = f"""Generate an incident report for:

INCIDENT:
- ID: {incident.incident_id}
- Title: {incident.title}
- Attack Type: {incident.attack_type}
- Severity: {incident.severity.value}
- Confidence: {incident.confidence}%
- Risk Score: {incident.risk_score}

AFFECTED ASSETS: {incident.affected_assets}
AFFECTED USERS: {incident.affected_users}
MITRE TECHNIQUES: {incident.mitre_techniques}

EVIDENCE:
{json.dumps(incident.evidence, indent=2)}

TIMELINE:
{json.dumps(incident.timeline, indent=2, default=str)}

REASONING:
{json.dumps(incident.reasoning, indent=2)}

Generate comprehensive technical and executive reports."""

        try:
            result = await self._call_llm(prompt, system_prompt)
            start = result.find("{")
            end = result.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(result[start:end])
            return {"technical_report": result, "executive_summary": "See technical report."}
        except Exception as e:
            logger.error("Report generation failed", error=str(e))
            return {"error": str(e)}

    async def natural_language_query(self, query: str, context: dict = None) -> str:
        """Handle natural language investigation queries."""
        system_prompt = """You are an AI SOC analyst assistant. Answer security investigation
queries using the provided context. Be precise and actionable."""

        prompt = f"""Investigation Query: {query}

Context:
{json.dumps(context or {}, indent=2, default=str)}

Provide a clear, actionable response."""

        return await self._call_llm(prompt, system_prompt)
