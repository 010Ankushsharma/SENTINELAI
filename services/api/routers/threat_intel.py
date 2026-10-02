"""Threat Intelligence endpoints."""
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class IOCLookupRequest(BaseModel):
    value: str
    type: str  # ip, domain, hash, etc.


class ThreatSearchRequest(BaseModel):
    query: str
    filter_type: str = None  # mitre_technique, cve, threat_report
    top_k: int = 5


@router.post("/lookup")
async def lookup_ioc(request: IOCLookupRequest):
    """Look up an IOC in threat intelligence databases."""
    return {"ioc": request.value, "type": request.type, "results": []}


@router.post("/search")
async def search_threat_intel(request: ThreatSearchRequest):
    """Semantic search over threat intelligence."""
    return {"query": request.query, "results": []}


@router.get("/mitre/{technique_id}")
async def get_mitre_technique(technique_id: str):
    """Get MITRE ATT&CK technique details."""
    return {"technique_id": technique_id}


@router.get("/cve/{cve_id}")
async def get_cve(cve_id: str):
    """Get CVE details."""
    return {"cve_id": cve_id}
