from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.db import get_db
from app.models.audit import AuditEvent
from app.services.audit_service import verify_audit_chain

router = APIRouter(prefix="/audit", tags=["Audit"])

@router.get("/events")
def events(db: Session = Depends(get_db)):
    rows = db.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(100)).all()
    return {"chain_valid": verify_audit_chain(db), "events": [
        {"id": x.id, "event_type": x.event_type, "actor": x.actor, "details": x.details,
         "event_hash": x.event_hash, "previous_hash": x.previous_hash, "created_at": x.created_at}
        for x in rows
    ]}

@router.get("/verify")
def verify(db: Session = Depends(get_db)):
    return {"valid": verify_audit_chain(db)}
