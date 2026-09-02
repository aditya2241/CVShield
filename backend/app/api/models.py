from pathlib import Path
import hashlib

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db import get_db
from app.models.model_artifact import ModelArtifact
from app.services.audit_service import append_audit
from app.services.hash_service import sha256_bytes
from app.services.assurance_service import model_assurance

router = APIRouter(prefix="/models", tags=["Model Assurance"])

MODEL_EXTENSIONS = {".onnx", ".pt", ".pth", ".torchscript", ".ts", ".bin"}


def inspect_model(filename: str, data: bytes):
    suffix = Path(filename).suffix.lower()
    indicators = []
    score = 0.0

    if suffix not in MODEL_EXTENSIONS:
        indicators.append("Model format is not one of the supported artifact extensions")
        score += 0.25
    else:
        indicators.append(f"Recognized model artifact format: {suffix}")

    if len(data) < 128:
        indicators.append("Model artifact is unusually small; manual review recommended")
        score += 0.35

    # Lightweight magic/header observations only. No deserialization or execution.
    if data.startswith(b"PK"):
        indicators.append("ZIP-based container header observed")
    elif data.startswith(b"\x89HDF"):
        indicators.append("HDF5 header observed")
    elif data.startswith(b"\x80\x04"):
        indicators.append("Python pickle-like header observed; do not execute untrusted artifacts")
        score += 0.15

    return {
        "anomaly_score": min(1.0, round(score, 3)),
        "indicators": indicators,
        "execution_performed": False,
        "sha256": sha256_bytes(data),
    }


@router.post("/register")
async def register_model(
    file: UploadFile = File(...),
    contributor: str = Form("web-user"),
    expected_sha256: str | None = Form(None),
    db: Session = Depends(get_db),
):
    if not file.filename:
        raise HTTPException(400, "Filename is required")

    data = await file.read(settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024 + 1)
    if len(data) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(413, "Model exceeds configured upload limit")

    filename = Path(file.filename).name
    digest = sha256_bytes(data)
    if expected_sha256 and (len(expected_sha256) != 64 or any(c not in "0123456789abcdefABCDEF" for c in expected_sha256)):
        raise HTTPException(400, "expected_sha256 must be a valid 64-character SHA-256 value")
    existing = db.scalar(select(ModelArtifact).where(ModelArtifact.sha256 == digest))
    if existing:
        return {
            "id": existing.id,
            "status": existing.status,
            "sha256": existing.sha256,
            "duplicate": True,
            "message": "Identical model fingerprint already registered",
        }

    inspection = inspect_model(filename, data)
    if expected_sha256 and expected_sha256.lower() != digest.lower():
        inspection["anomaly_score"] = max(inspection["anomaly_score"], 0.8)
        inspection["indicators"].append("Reference SHA-256 does not match the uploaded model artifact")
        inspection["reference_hash_verified"] = False
    else:
        inspection["reference_hash_verified"] = True
    inspection["assurance"] = model_assurance(filename, data)
    inspection["anomaly_score"] = max(inspection["anomaly_score"], inspection["assurance"]["anomaly_score"])
    inspection["indicators"] = list(dict.fromkeys(inspection["indicators"] + inspection["assurance"]["indicators"] + inspection["assurance"]["warnings"]))
    status = "REVIEW" if inspection["anomaly_score"] >= 0.25 else "TRUSTED"

    record = ModelArtifact(
        filename=filename,
        size_bytes=len(data),
        sha256=digest,
        uploader=contributor[:255],
        status=status,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    append_audit(db, "MODEL_REGISTERED", contributor[:255], {
        "model_id": record.id,
        "filename": filename,
        "sha256": digest,
        "status": status,
        "indicators": inspection["indicators"],
    })

    return {
        "id": record.id,
        "filename": filename,
        "size_bytes": len(data),
        "sha256": digest,
        "status": status,
        "inspection": inspection,
    }


@router.post("/{model_id}/verify")
def verify_model(model_id: int, expected_sha256: str, db: Session = Depends(get_db)):
    record = db.get(ModelArtifact, model_id)
    if not record:
        raise HTTPException(404, "Model artifact not found")
    valid = expected_sha256.lower() == record.sha256.lower()
    record.status = "TRUSTED" if valid else "TAMPERED"
    db.commit()
    append_audit(db, "MODEL_VERIFIED" if valid else "MODEL_TAMPER_DETECTED", "web-user", {
        "model_id": model_id, "valid": valid, "stored_sha256": record.sha256, "provided_sha256": expected_sha256
    })
    return {"model_id": model_id, "valid": valid, "status": record.status, "stored_sha256": record.sha256, "provided_sha256": expected_sha256}


@router.get("")
def list_models(db: Session = Depends(get_db)):
    rows = db.scalars(select(ModelArtifact).order_by(ModelArtifact.id.desc()).limit(100)).all()
    return [
        {
            "id": r.id,
            "filename": r.filename,
            "size_bytes": r.size_bytes,
            "sha256": r.sha256,
            "status": r.status,
            "uploader": r.uploader,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]
