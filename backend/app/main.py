from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from app.core.config import settings
from app.db import Base, engine
from app.models import User, AuditEvent, Dataset, ModelArtifact, InferenceRecord

from app.api.auth import router as auth_router
from app.api.integrity import router as integrity_router
from app.api.audit import router as audit_router
from app.api.datasets import router as datasets_router
from app.api.risk import router as risk_router
from app.api.health import router as health_router
from app.api.models import router as models_router
from app.api.inference import router as inference_router
from app.api.assurance import router as assurance_router
from app.api.report import router as report_router


# ---------------------------------------------------------
# Upload directory
# ---------------------------------------------------------

Path(settings.UPLOAD_DIR).mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------
# Database initialization
# ---------------------------------------------------------

Base.metadata.create_all(bind=engine)


# ---------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------

app = FastAPI(
    title=settings.APP_NAME,
    version="2.1.0",
    description=(
        "TrustGuard AI computer-vision integrity assurance platform. "
        "Non-executing evidence analysis, model fingerprinting, "
        "inference provenance and tamper-evident audit."
    ),
)


# ---------------------------------------------------------
# GZip compression
# ---------------------------------------------------------

app.add_middleware(
    GZipMiddleware,
    minimum_size=1000,
)


# ---------------------------------------------------------
# CORS CONFIGURATION
# ---------------------------------------------------------
#
# Frontend:
# https://cvshield-1.onrender.com
#
# Backend:
# https://cvshield.onrender.com
#
# Local development:
# http://localhost:5173
# http://127.0.0.1:5173
# ---------------------------------------------------------

allowed_origins = list(
    set(
        settings.cors_origins_list
        + [
            "https://cvshield-1.onrender.com",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ]
    )
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# ---------------------------------------------------------
# API Routers
# ---------------------------------------------------------

app.include_router(
    auth_router,
    prefix="/api",
)

app.include_router(
    integrity_router,
    prefix="/api",
)

app.include_router(
    audit_router,
    prefix="/api",
)

app.include_router(
    datasets_router,
    prefix="/api",
)

app.include_router(
    risk_router,
    prefix="/api",
)

app.include_router(
    health_router,
    prefix="/api",
)

app.include_router(
    models_router,
    prefix="/api",
)

app.include_router(
    inference_router,
    prefix="/api",
)

app.include_router(
    assurance_router,
    prefix="/api",
)

app.include_router(
    report_router,
    prefix="/api",
)


# ---------------------------------------------------------
# Health Check
# ---------------------------------------------------------

@app.get("/health")
def root_health():
    return {
        "status": "healthy",
        "service": "trustguard-backend",
    }


# ---------------------------------------------------------
# Root Endpoint
# ---------------------------------------------------------

@app.get("/")
def root():
    return {
        "application": settings.APP_NAME,
        "status": "online",
        "capabilities": [
            "dataset-integrity",
            "non-executing-anomaly-analysis",
            "model-fingerprinting",
            "inference-provenance",
            "tamper-evident-audit",
            "explainable-risk",
            "distribution-shift-assessment",
            "COCO-and-YOLO-aware-dataset-analysis",
            "safe-non-executing-model-inspection",
            "assurance-summary-report",
        ],
    }