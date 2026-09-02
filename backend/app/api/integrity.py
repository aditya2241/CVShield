from pathlib import Path
import json

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db import get_db
from app.models.dataset import Dataset
from app.services.audit_service import append_audit
from app.services.risk_service import calculate_risk
from app.services.upload_service import stream_upload
from app.services.assurance_service import dataset_assurance

router = APIRouter(prefix="/integrity", tags=["Integrity"])

SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".scr", ".msi", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse"}
SCRIPT_EXTENSIONS = {".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse"}
TEXT_EXTENSIONS = {".txt", ".csv", ".json", ".xml", ".html", ".htm", ".md", ".log", ".py", ".java", ".c", ".cpp", ".js", ".ts", ".css"}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".webp", ".gif"}
DATASET_EXTENSIONS = {".csv", ".json", ".txt", ".xml", ".yaml", ".yml", ".zip"}


def _format_signals(filename: str, mime_type: str, data: bytes):
    name = Path(filename).name
    suffix = Path(name).suffix.lower()
    reasons: list[str] = []
    score = 0.0
    metadata_anomaly = False
    format_info = "generic artifact"

    if suffix in SUSPICIOUS_EXTENSIONS:
        score += 0.45
        reasons.append(f"Executable or script extension detected: {suffix}")

    suffixes = [s.lower() for s in Path(name).suffixes]
    if len(suffixes) >= 2 and suffixes[-2] in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"} and suffix in SUSPICIOUS_EXTENSIONS:
        score += 0.35
        metadata_anomaly = True
        reasons.append("Double-extension filename pattern detected")

    if mime_type and suffix in SCRIPT_EXTENSIONS and not (
        "script" in mime_type.lower() or "text" in mime_type.lower() or mime_type.lower() == "application/octet-stream"
    ):
        score += 0.15
        metadata_anomaly = True
        reasons.append("MIME type is inconsistent with the file extension")

    if data.startswith(b"MZ"):
        score += 0.35
        reasons.append("Windows PE executable header detected")

    if suffix in IMAGE_EXTENSIONS or (mime_type and mime_type.startswith("image/")):
        format_info = "image artifact"
        if len(data) < 64:
            score += 0.25
            reasons.append("Image artifact is unusually small")

    if suffix == ".csv":
        format_info = "CSV dataset"
        try:
            first_line = data[:8192].decode("utf-8", errors="ignore").splitlines()[0]
            if "," not in first_line and "\t" not in first_line:
                score += 0.10
                reasons.append("CSV delimiter/header structure could not be confirmed")
        except (IndexError, UnicodeDecodeError):
            score += 0.10
            reasons.append("CSV structure could not be confirmed")

    if suffix == ".json":
        format_info = "JSON/annotation candidate"
        try:
            obj = json.loads(data[:5 * 1024 * 1024].decode("utf-8", errors="strict"))
            if isinstance(obj, dict) and {"images", "annotations"}.issubset(obj.keys()):
                format_info = "COCO-style annotation candidate"
                if not isinstance(obj.get("images"), list) or not isinstance(obj.get("annotations"), list):
                    score += 0.25
                    reasons.append("COCO-style images/annotations fields have unexpected types")
            elif isinstance(obj, dict):
                reasons.append("Valid JSON dataset metadata observed")
        except (ValueError, UnicodeDecodeError):
            score += 0.20
            metadata_anomaly = True
            reasons.append("JSON extension but content is not valid JSON")

    if suffix == ".txt":
        lines = data[:1024 * 1024].decode("utf-8", errors="ignore").splitlines()
        nonempty = [line.strip() for line in lines if line.strip()][:100]
        if nonempty and all(len(line.split()) == 5 for line in nonempty):
            format_info = "YOLO-label candidate"
            reasons.append("YOLO-style five-field label rows observed")

    sample = data[:1024 * 1024]
    if suffix in TEXT_EXTENSIONS or (mime_type and mime_type.startswith("text/")):
        text = sample.decode("utf-8", errors="ignore").lower()
        indicators = [
            "powershell -enc", "invoke-expression", "downloadstring(",
            "frombase64string(", "wscript.shell", "cmd.exe /c", "certutil -decode",
        ]
        hits = [indicator for indicator in indicators if indicator in text]
        if hits:
            score += min(0.50, 0.18 * len(hits))
            reasons.append(f"Suspicious script/content indicators detected ({len(hits)})")

    if len(data) > 50 * 1024 * 1024 and data[:4] in {b"PK\x03\x04", b"\x1f\x8b\x08\x00"}:
        score += 0.10
        reasons.append("Large compressed archive detected; deeper inspection recommended")

    return max(0.0, min(1.0, score)), metadata_anomaly, reasons, format_info


def analyze_uploaded_file(filename: str, mime_type: str, data: bytes, duplicate: bool = False, expected_hash: str | None = None, digest: str | None = None):
    anomaly_score, metadata_anomaly, reasons, format_info = _format_signals(filename, mime_type, data)

    if duplicate:
        reasons.append("Exact fingerprint already exists in the registry")
        anomaly_score = max(anomaly_score, 0.20)

    integrity = True
    if expected_hash:
        integrity = expected_hash.lower() == (digest or "").lower()
        if not integrity:
            reasons.append("Supplied reference SHA-256 does not match the uploaded artifact")
            metadata_anomaly = True

    risk = calculate_risk(
        dataset_integrity=integrity,
        model_integrity=True,
        inference_integrity=True,
        anomaly_score=anomaly_score,
        metadata_anomaly=metadata_anomaly,
    )
    if reasons:
        risk["risk_factors"] = reasons + [f for f in risk["risk_factors"] if f not in reasons]

    return {
        "risk": risk,
        "verdict": risk["recommended_action"],
        "anomaly_score": round(anomaly_score, 3),
        "metadata_anomaly": metadata_anomaly,
        "indicators": reasons,
        "format": format_info,
        "reference_hash_verified": integrity,
        "execution_performed": False,
    }


@router.post("/scan")
async def scan(
    file: UploadFile = File(...),
    contributor: str = Form("web-user"),
    expected_sha256: str | None = Form(None),
    db: Session = Depends(get_db),
):
    if not file.filename:
        raise HTTPException(400, "Filename is required")

    filename = Path(file.filename).name
    if filename in {"", ".", ".."}:
        raise HTTPException(400, "Invalid filename")
    if expected_sha256 and (len(expected_sha256) != 64 or any(c not in "0123456789abcdefABCDEF" for c in expected_sha256)):
        raise HTTPException(400, "expected_sha256 must be a valid 64-character SHA-256 value")

    stored_path, size, digest, sample = await stream_upload(file)
    mime = file.content_type or "application/octet-stream"
    duplicate = db.scalar(select(Dataset).where(Dataset.sha256 == digest)) is not None

    analysis = analyze_uploaded_file(filename, mime, sample, duplicate, expected_sha256, digest)
    deep = dataset_assurance(filename, mime, sample)
    analysis["dataset_assurance"] = deep
    analysis["anomaly_score"] = max(analysis["anomaly_score"], deep["anomaly_score"])
    analysis["indicators"] = list(dict.fromkeys(analysis["indicators"] + deep["indicators"] + deep["warnings"]))
    # Recompute risk using the strongest offline evidence signal.
    analysis["risk"] = calculate_risk(
        dataset_integrity=analysis["reference_hash_verified"],
        model_integrity=True, inference_integrity=True,
        anomaly_score=analysis["anomaly_score"],
        metadata_anomaly=analysis["metadata_anomaly"],
    )
    analysis["risk"]["risk_factors"] = analysis["indicators"] + [x for x in analysis["risk"]["risk_factors"] if x not in analysis["indicators"]]
    status = "REVIEW" if analysis["risk"]["risk_score"] >= 25 else "VERIFIED"

    dataset = Dataset(
        filename=filename,
        size_bytes=size,
        sha256=digest,
        mime_type=mime,
        uploader=contributor[:255],
        integrity_status=status,
    )
    db.add(dataset)
    db.commit()
    db.refresh(dataset)

    append_audit(db, "FILE_SCANNED", contributor[:255], {
        "dataset_id": dataset.id,
        "filename": filename,
        "sha256": digest,
        "size": size,
        "contributor": contributor[:255],
        "risk_score": analysis["risk"]["risk_score"],
        "risk_level": analysis["risk"]["risk_level"],
        "indicators": analysis["indicators"],
        "stored_artifact": stored_path.name,
    })

    return {
        "id": dataset.id,
        "filename": filename,
        "size_bytes": size,
        "sha256": digest,
        "mime_type": mime,
        "status": status,
        "risk_score": analysis["risk"]["risk_score"],
        "risk_level": analysis["risk"]["risk_level"],
        "risk_factors": analysis["risk"]["risk_factors"],
        "recommended_action": analysis["risk"]["recommended_action"],
        "confidence": analysis["risk"]["confidence"],
        "message": "Artifact fingerprinted, analyzed and registered without execution",
        "analysis": analysis,
    }
