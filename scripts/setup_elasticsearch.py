"""Setup Elasticsearch indexes for SentinelAI."""
from elasticsearch import Elasticsearch

es = Elasticsearch("http://localhost:9200")

INDEXES = {
    "security-events": {
        "mappings": {
            "properties": {
                "event_id": {"type": "keyword"},
                "timestamp": {"type": "date"},
                "source": {"type": "keyword"},
                "category": {"type": "keyword"},
                "action": {"type": "keyword"},
                "outcome": {"type": "keyword"},
                "source_ip": {"type": "ip"},
                "dest_ip": {"type": "ip"},
                "user": {"type": "keyword"},
                "hostname": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "raw_message": {"type": "text"},
            }
        },
        "settings": {"number_of_shards": 5, "number_of_replicas": 1},
    },
    "detections": {
        "mappings": {
            "properties": {
                "detection_id": {"type": "keyword"},
                "timestamp": {"type": "date"},
                "rule_name": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "confidence": {"type": "float"},
                "description": {"type": "text"},
                "mitre_techniques": {"type": "keyword"},
            }
        },
        "settings": {"number_of_shards": 3, "number_of_replicas": 1},
    },
    "incidents": {
        "mappings": {
            "properties": {
                "incident_id": {"type": "keyword"},
                "created_at": {"type": "date"},
                "title": {"type": "text"},
                "attack_type": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "status": {"type": "keyword"},
                "confidence": {"type": "float"},
                "risk_score": {"type": "float"},
                "affected_assets": {"type": "keyword"},
                "affected_users": {"type": "keyword"},
                "mitre_techniques": {"type": "keyword"},
            }
        },
        "settings": {"number_of_shards": 2, "number_of_replicas": 1},
    },
}

for index_name, config in INDEXES.items():
    if not es.indices.exists(index=index_name):
        es.indices.create(index=index_name, body=config)
        print(f"Created index: {index_name}")
    else:
        print(f"Index already exists: {index_name}")
