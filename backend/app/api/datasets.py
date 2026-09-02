from sqlalchemy import select
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db import get_db
from app.models.dataset import Dataset

router = APIRouter(prefix="/datasets", tags=["Datasets"])

@router.get("")
def list_datasets(db: Session = Depends(get_db)):
    rows = db.scalars(select(Dataset).order_by(Dataset.id.desc())).all()
    return [{
        "id": x.id,
        "filename": x.filename,
        "size_bytes": x.size_bytes,
        "sha256": x.sha256,
        "mime_type": x.mime_type,
        "status": x.integrity_status,
        "uploader": x.uploader,
        "created_at": x.created_at.isoformat(),
    } for x in rows]
