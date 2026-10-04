"""RAG-based Threat Intelligence engine using Qdrant."""
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance, VectorParams, PointStruct,
    Filter, FieldCondition, MatchValue,
)
from sentence_transformers import SentenceTransformer
from shared.config import get_settings
from shared.utils.logging import get_logger
import uuid

logger = get_logger(__name__)

COLLECTION_NAME = "threat_intelligence"
EMBEDDING_DIM = 1024  # bge-large-en-v1.5


class ThreatIntelRAG:
    """RAG system for threat intelligence retrieval."""

    def __init__(self):
        settings = get_settings()
        self.client = QdrantClient(host=settings.qdrant_host, port=settings.qdrant_port)
        self.model = None  # Lazy load

    def _load_model(self):
        if self.model is None:
            self.model = SentenceTransformer("BAAI/bge-large-en-v1.5")
            logger.info("Embedding model loaded")

    async def initialize(self):
        """Create collection if not exists."""
        collections = self.client.get_collections().collections
        if not any(c.name == COLLECTION_NAME for c in collections):
            self.client.create_collection(
                collection_name=COLLECTION_NAME,
                vectors_config=VectorParams(size=EMBEDDING_DIM, distance=Distance.COSINE),
            )
            logger.info("Threat intelligence collection created")

    def embed(self, text: str) -> list[float]:
        self._load_model()
        return self.model.encode(text, normalize_embeddings=True).tolist()

    async def ingest_mitre_technique(self, technique: dict):
        """Ingest a MITRE ATT&CK technique."""
        text = f"{technique['id']}: {technique['name']}. {technique.get('description', '')}"
        vector = self.embed(text)
        self.client.upsert(
            collection_name=COLLECTION_NAME,
            points=[
                PointStruct(
                    id=str(uuid.uuid4()),
                    vector=vector,
                    payload={
                        "type": "mitre_technique",
                        "technique_id": technique["id"],
                        "name": technique["name"],
                        "tactic": technique.get("tactic", ""),
                        "description": technique.get("description", ""),
                        "text": text,
                    },
                )
            ],
        )

    async def ingest_cve(self, cve: dict):
        """Ingest a CVE entry."""
        text = f"{cve['id']}: {cve.get('description', '')}"
        vector = self.embed(text)
        self.client.upsert(
            collection_name=COLLECTION_NAME,
            points=[
                PointStruct(
                    id=str(uuid.uuid4()),
                    vector=vector,
                    payload={
                        "type": "cve",
                        "cve_id": cve["id"],
                        "severity": cve.get("severity", "unknown"),
                        "description": cve.get("description", ""),
                        "text": text,
                    },
                )
            ],
        )

    async def ingest_threat_report(self, report: dict):
        """Ingest a threat report."""
        text = f"{report['title']}. {report.get('summary', '')}"
        vector = self.embed(text)
        self.client.upsert(
            collection_name=COLLECTION_NAME,
            points=[
                PointStruct(
                    id=str(uuid.uuid4()),
                    vector=vector,
                    payload={
                        "type": "threat_report",
                        "title": report["title"],
                        "source": report.get("source", ""),
                        "date": report.get("date", ""),
                        "text": text,
                    },
                )
            ],
        )

    async def search(self, query: str, top_k: int = 5, filter_type: str = None) -> list[dict]:
        """Semantic search over threat intelligence."""
        vector = self.embed(query)
        
        search_filter = None
        if filter_type:
            search_filter = Filter(
                must=[FieldCondition(key="type", match=MatchValue(value=filter_type))]
            )

        results = self.client.search(
            collection_name=COLLECTION_NAME,
            query_vector=vector,
            query_filter=search_filter,
            limit=top_k,
        )

        return [
            {
                "score": hit.score,
                "payload": hit.payload,
            }
            for hit in results
        ]

    async def lookup_ioc(self, ioc_value: str) -> list[dict]:
        """Look up an IOC in the threat intelligence database."""
        return await self.search(f"indicator of compromise: {ioc_value}", top_k=3)

    async def get_mitre_context(self, technique_ids: list[str]) -> list[dict]:
        """Get context for MITRE technique IDs."""
        results = []
        for tid in technique_ids:
            hits = await self.search(
                f"MITRE ATT&CK technique {tid}",
                top_k=1,
                filter_type="mitre_technique",
            )
            results.extend(hits)
        return results
