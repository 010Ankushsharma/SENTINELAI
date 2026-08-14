# SentinelAI: Autonomous SOC Analyst Platform

Enterprise-grade AI-powered Security Operations Center (SOC) analyst.

## Architecture

```
Security Sources → Kafka → Normalization → Detection → Investigation → LLM Analyst → Reports
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Streaming | Apache Kafka |
| SIEM | Elastic Stack |
| AI/LLM | Llama 3.1/4 via Ollama |
| Vector DB | Qdrant |
| Graph DB | Neo4j |
| Backend | FastAPI + Python |
| Frontend | React + TypeScript |
| Database | PostgreSQL |
| Orchestration | Kubernetes + Docker |

## Quick Start

```bash
# Start infrastructure
docker-compose up -d

# Start API server
cd services/api && uvicorn main:app --reload

# Start frontend
cd frontend && npm start
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| API Gateway | 8000 | FastAPI REST API |
| Kafka | 9092 | Event streaming |
| Elasticsearch | 9200 | Log storage & search |
| Kibana | 5601 | Dashboards |
| Neo4j | 7474 | Graph database |
| Qdrant | 6333 | Vector database |
| PostgreSQL | 5432 | Relational data |
| Frontend | 3000 | React dashboard |

## License
Proprietary - Internal Use Only
