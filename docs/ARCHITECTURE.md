# SentinelAI Architecture

## System Overview

```
┌────────────────────┐
│ Security Sources   │
└─────────┬──────────┘
          │
┌─────────▼──────────┐
│ Kafka Streaming    │  ← raw_logs topic
└─────────┬──────────┘
          │
┌─────────▼──────────┐
│ Log Normalization  │  ← normalized_logs topic
└─────────┬──────────┘
          │
┌─────────▼──────────┐
│ Detection Engine   │  ← detections topic
│ (Sigma + ML + AI)  │
└─────────┬──────────┘
          │
┌─────────▼──────────┐
│ Investigation      │  ← incidents topic
│ (Graph + Corr.)    │
└─────────┬──────────┘
          │
┌─────────▼──────────┐
│ LLM Analyst        │
│ (Llama 3.1/4)      │
└─────────┬──────────┘
          │
┌─────────▼──────────┐
│ Reports & Actions  │
└────────────────────┘
```

## Multi-Agent Architecture

| Agent | Role |
|-------|------|
| Detection Agent | Classify threats, reduce false positives |
| Investigation Agent | Gather context, query logs and graph |
| Threat Intel Agent | IOC enrichment, CVE lookup, MITRE mapping |
| Reporting Agent | Generate incident and executive reports |
| Response Agent | Recommend containment and remediation |

## Data Flow

1. **Ingestion**: Syslog, API webhooks, file-based
2. **Streaming**: Kafka topics for each pipeline stage
3. **Storage**: Elasticsearch (events), Neo4j (relationships), Qdrant (threat intel), PostgreSQL (config)
4. **Detection**: Sigma rules + ML anomaly detection
5. **Investigation**: Graph traversal + event correlation
6. **Analysis**: LLM reasoning with RAG context
7. **Response**: Automated playbooks + reports
