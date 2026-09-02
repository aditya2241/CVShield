import hashlib
import json
from sqlalchemy import select, text
from sqlalchemy.orm import Session
from app.models.audit import AuditEvent


def _acquire_chain_lock(db: Session):
    """Serialize audit append operations so concurrent users cannot fork the chain."""
    bind = db.get_bind()
    dialect = bind.dialect.name
    if dialect == "sqlite":
        # SQLite's RESERVED write lock prevents two workers from selecting the
        # same previous event before either insert commits.
        db.connection().exec_driver_sql("BEGIN IMMEDIATE")
    elif dialect == "postgresql":
        # Transaction-scoped advisory lock; value is specific to this app's chain.
        db.execute(text("SELECT pg_advisory_xact_lock(26228)"))


def append_audit(db: Session, event_type: str, actor: str, details: dict):
    try:
        _acquire_chain_lock(db)
        previous = db.scalar(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1))
        previous_hash = previous.event_hash if previous else ""
        payload = {
            "event_type": event_type,
            "actor": actor,
            "details": details,
            "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()
        event = AuditEvent(
            event_type=event_type,
            actor=actor,
            details=json.dumps(details, sort_keys=True, ensure_ascii=False),
            event_hash=event_hash,
            previous_hash=previous_hash,
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event
    except Exception:
        db.rollback()
        raise


def verify_audit_chain(db: Session) -> bool:
    events = db.scalars(select(AuditEvent).order_by(AuditEvent.id)).all()
    previous = ""
    for event in events:
        payload = {
            "event_type": event.event_type,
            "actor": event.actor,
            "details": json.loads(event.details),
            "previous_hash": event.previous_hash,
        }
        expected = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()
        if event.previous_hash != previous or event.event_hash != expected:
            return False
        previous = event.event_hash
    return True
