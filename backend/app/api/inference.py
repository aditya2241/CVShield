from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db import get_db
from app.models.inference import InferenceRecord
from app.schemas.inference import InferenceCreateRequest, InferenceVerifyRequest
from app.services.audit_service import append_audit
from app.services.provenance_service import make_provenance_signature, sha256_json, verify_provenance_signature

router = APIRouter(prefix="/inference", tags=["Inference Provenance"])


def _record_payload(input_sha256: str, model_sha256: str, config_sha256: str, output_sha256: str):
    return {
        "input_sha256": input_sha256,
        "model_sha256": model_sha256,
        "config_sha256": config_sha256,
        "output_sha256": output_sha256,
    }


@router.post("/records")
def create_record(data: InferenceCreateRequest, db: Session = Depends(get_db)):
    config_sha256 = sha256_json(data.configuration)
    output_sha256 = sha256_json(data.output)
    payload = _record_payload(data.input_sha256, data.model_sha256, config_sha256, output_sha256)
    provenance_sha256 = sha256_json(payload)
    signature = make_provenance_signature(payload, settings.SECRET_KEY)

    record = InferenceRecord(
        input_sha256=data.input_sha256,
        model_sha256=data.model_sha256,
        config_sha256=config_sha256,
        output_sha256=output_sha256,
        provenance_sha256=provenance_sha256,
        signature=signature,
        actor=data.actor,
        status="VERIFIED",
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    append_audit(db, "INFERENCE_RECORDED", data.actor, {
        "record_id": record.id,
        "provenance_sha256": provenance_sha256,
        "input_sha256": data.input_sha256,
        "model_sha256": data.model_sha256,
    })

    return {
        "id": record.id,
        "status": record.status,
        "provenance_sha256": provenance_sha256,
        "signature": signature,
        "input_sha256": record.input_sha256,
        "model_sha256": record.model_sha256,
        "config_sha256": record.config_sha256,
        "output_sha256": record.output_sha256,
        "message": "Inference provenance bound to input, model, configuration and output",
    }


@router.post("/records/{record_id}/verify")
def verify_record(record_id: int, data: InferenceVerifyRequest, db: Session = Depends(get_db)):
    record = db.get(InferenceRecord, record_id)
    if not record:
        raise HTTPException(404, "Inference record not found")

    config_sha256 = sha256_json(data.configuration)
    output_sha256 = sha256_json(data.output)
    payload = _record_payload(record.input_sha256, record.model_sha256, config_sha256, output_sha256)
    expected_provenance = sha256_json(payload)
    valid = expected_provenance == record.provenance_sha256 and verify_provenance_signature(
        payload, record.signature, settings.SECRET_KEY
    )

    record.status = "VERIFIED" if valid else "TAMPERED"
    db.commit()

    append_audit(db, "INFERENCE_VERIFIED" if valid else "INFERENCE_TAMPER_DETECTED", "web-user", {
        "record_id": record.id,
        "valid": valid,
        "expected_provenance": expected_provenance,
        "stored_provenance": record.provenance_sha256,
    })

    return {
        "record_id": record.id,
        "valid": valid,
        "status": record.status,
        "expected_provenance_sha256": expected_provenance,
        "stored_provenance_sha256": record.provenance_sha256,
        "message": "Inference provenance verified" if valid else "Inference tampering detected",
    }


@router.get("/records")
def list_records(db: Session = Depends(get_db)):
    rows = db.scalars(select(InferenceRecord).order_by(InferenceRecord.id.desc()).limit(100)).all()
    return [
        {
            "id": r.id,
            "status": r.status,
            "input_sha256": r.input_sha256,
            "model_sha256": r.model_sha256,
            "config_sha256": r.config_sha256,
            "output_sha256": r.output_sha256,
            "provenance_sha256": r.provenance_sha256,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]
