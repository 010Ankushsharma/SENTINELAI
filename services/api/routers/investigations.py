"""Investigation endpoints - natural language queries."""
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class InvestigationQuery(BaseModel):
    query: str
    context: dict = {}


class InvestigationResponse(BaseModel):
    query: str
    response: str
    sources: list[dict] = []
    related_incidents: list[str] = []


@router.post("/query", response_model=InvestigationResponse)
async def investigate(query: InvestigationQuery):
    """Natural language investigation query.
    
    Examples:
    - "Show all hosts communicating with malicious IPs in last 24 hours"
    - "Find users affected by incident #234"
    - "What MITRE techniques were used in the latest attack?"
    """
    # In production: route to LLM analyst with context from ES/Neo4j
    return InvestigationResponse(
        query=query.query,
        response="Investigation in progress...",
    )


@router.get("/attack-path/{entity_type}/{entity_value}")
async def get_attack_path(entity_type: str, entity_value: str, depth: int = 5):
    """Get attack path from graph database."""
    # In production: query Neo4j
    return {"entity_type": entity_type, "entity_value": entity_value, "paths": []}


@router.get("/lateral-movement/{user}")
async def check_lateral_movement(user: str):
    """Check for lateral movement by a user."""
    return {"user": user, "hosts": [], "suspicious": False}
