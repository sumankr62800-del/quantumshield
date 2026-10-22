
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.auth import router as auth_router
from backend.app.api.messages import router as messages_router
from backend.app.api.security import router as security_router
from backend.app.api.dashboard import router as dashboard_router

from backend.app.database.connection import Base, engine

# Import models so SQLAlchemy registers their tables.
from backend.app.models.user import User
from backend.app.models.message import Message
from backend.app.models.security_event import SecurityEvent

from backend.app.core.config import settings


# ============================================================
# APPLICATION ENVIRONMENT
# ============================================================

APP_ENV = settings.APP_ENV
IS_PRODUCTION = APP_ENV == "production"


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

# Temporary compatibility measure for existing databases
# and tests. Production should eventually use Alembic
# migrations instead of automatic schema creation.
Base.metadata.create_all(bind=engine)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "AI-Driven Post-Quantum Secure Communication "
        "& Threat Detection Platform"
    ),
    version=settings.APP_VERSION,
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None if IS_PRODUCTION else "/redoc",
    openapi_url=None if IS_PRODUCTION else "/openapi.json",
)


# ============================================================
# CORS CONFIGURATION
# ============================================================

default_origins = (
    "http://localhost:5173,"
    "http://127.0.0.1:5173"
)

cors_origins = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS",
        default_origins if not IS_PRODUCTION else "",
    ).split(",")
    if origin.strip()
]

if IS_PRODUCTION and not cors_origins:
    raise RuntimeError(
        "CORS_ORIGINS must be configured in production."
    )

if "*" in cors_origins:
    raise RuntimeError(
        "Wildcard CORS origins are not allowed."
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.get("/")
def root():
    return {
        "message": "QuantumShield API is running",
        "status": "online",
        "version": settings.APP_VERSION,
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


# ============================================================
# API ROUTERS
# ============================================================

app.include_router(auth_router)
app.include_router(messages_router)
app.include_router(security_router)
app.include_router(dashboard_router)
