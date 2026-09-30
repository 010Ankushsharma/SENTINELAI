from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Any
from enum import Enum


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    FILE_NAME = "file_name"
    CVE = "cve"


class ThreatIndicator(BaseModel):
    ioc_id: str
    type: IOCType
    value: str
    threat_type: str  # malware, phishing, c2, botnet, etc.
    confidence: float = Field(ge=0, le=100)
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class MITRETechnique(BaseModel):
    technique_id: str  # e.g. T1059.001
    name: str
    tactic: str
    description: str
    platforms: list[str] = Field(default_factory=list)
    detection: Optional[str] = None
    url: str = ""
