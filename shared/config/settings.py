from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # Kafka
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_group_id: str = "sentinelai"

    # Elasticsearch
    es_host: str = "localhost"
    es_port: int = 9200
    es_user: str = "elastic"
    es_password: str = "changeme"

    # Neo4j
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "changeme"

    # Qdrant
    qdrant_host: str = "localhost"
    qdrant_port: int = 6333

    # PostgreSQL
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "sentinelai"
    postgres_user: str = "sentinelai"
    postgres_password: str = "changeme"

    # LLM
    llm_base_url: str = "http://localhost:11434"
    llm_model: str = "llama3.1:70b"

    # Security
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expiration_minutes: int = 60

    # App
    log_level: str = "INFO"
    environment: str = "development"

    @property
    def postgres_dsn(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def es_url(self) -> str:
        return f"http://{self.es_host}:{self.es_port}"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
