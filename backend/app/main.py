from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.auth import router as auth_router
from backend.app.api.messages import router as messages_router
from backend.app.api.security import router as security_router
from backend.app.api.dashboard import router as dashboard_router

from backend.app.database.connection import Base, engine

from backend.app.models.user import User
from backend.app.models.message import Message
from backend.app.models.security_event import SecurityEvent


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

Base.metadata.create_all(bind=engine)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="QuantumShield",
    description=(
        "AI-Driven Post-Quantum Secure Communication "
        "& Threat Detection Platform"
    ),
    version="1.0.0",
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "message": "QuantumShield API is running",
        "status": "online",
        "version": "1.0.0",
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