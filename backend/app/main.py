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

Path(settings.UPLOAD_DIR).mkdir(parents=True, exist_ok=True)
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.APP_NAME,
    version="2.1.0",
    description=(
        "TrustGuard AI — SIH26228 computer-vision integrity assurance platform. "
        "Non-executing evidence analysis, model fingerprinting, inference provenance "
        "and tamper-evident audit."
    ),
)

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/api")
app.include_router(integrity_router, prefix="/api")
app.include_router(audit_router, prefix="/api")
app.include_router(datasets_router, prefix="/api")
app.include_router(risk_router, prefix="/api")
app.include_router(health_router, prefix="/api")
app.include_router(models_router, prefix="/api")
app.include_router(inference_router, prefix="/api")
app.include_router(assurance_router, prefix="/api")
app.include_router(report_router, prefix="/api")


@app.get("/health")
def root_health():
    return {"status": "healthy", "service": "trustguard-backend"}


@app.get("/")
def root():
    return {
        "application": settings.APP_NAME,
        "problem_statement": "SIH26228",
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
            "distribution-shift-analysis",
            "assurance-summary-report",
        ],
    }
