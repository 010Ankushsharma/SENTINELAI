"""FastAPI application - SentinelAI API Gateway."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from shared.config import get_settings
from shared.utils.logging import get_logger
from .routers import alerts, incidents, investigations, threat_intel, dashboard, auth

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("SentinelAI API starting up")
    # Initialize connections
    yield
    logger.info("SentinelAI API shutting down")


app = FastAPI(
    title="SentinelAI",
    description="Autonomous SOC Analyst Platform API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["Alerts"])
app.include_router(incidents.router, prefix="/api/v1/incidents", tags=["Incidents"])
app.include_router(investigations.router, prefix="/api/v1/investigations", tags=["Investigations"])
app.include_router(threat_intel.router, prefix="/api/v1/threat-intel", tags=["Threat Intelligence"])
app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["Dashboard"])


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "SentinelAI"}
