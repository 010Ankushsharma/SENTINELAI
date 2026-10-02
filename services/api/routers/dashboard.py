"""Dashboard data endpoints."""
from fastapi import APIRouter
from datetime import datetime

router = APIRouter()


@router.get("/summary")
async def get_dashboard_summary():
    """Get SOC dashboard summary stats."""
    return {
        "total_alerts_24h": 0,
        "critical_alerts": 0,
        "active_incidents": 0,
        "mean_time_to_detect": "0s",
        "mean_time_to_respond": "0s",
        "false_positive_rate": 0.0,
        "alerts_by_severity": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        },
        "top_attack_types": [],
        "top_mitre_techniques": [],
        "risk_score": 0,
        "last_updated": datetime.utcnow().isoformat(),
    }


@router.get("/threat-map")
async def get_threat_map():
    """Get geolocation data for threat visualization."""
    return {"threats": []}


@router.get("/mitre-matrix")
async def get_mitre_matrix():
    """Get MITRE ATT&CK matrix coverage."""
    return {"techniques": [], "coverage": {}}


@router.get("/timeline")
async def get_event_timeline(hours: int = 24):
    """Get event timeline for the dashboard."""
    return {"hours": hours, "events": []}
