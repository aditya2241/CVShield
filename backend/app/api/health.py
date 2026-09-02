from time import perf_counter
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.db import get_db
from app.core.config import settings

router = APIRouter(prefix="/health", tags=["System"])


@router.get("")
def health(db: Session = Depends(get_db)):
    started = perf_counter()
    db.execute(text("SELECT 1"))
    latency_ms = round((perf_counter() - started) * 1000, 2)
    return {
        "status": "healthy",
        "service": "trustguard-backend",
        "database": "connected",
        "database_latency_ms": latency_ms,
        "environment": settings.ENVIRONMENT,
    }


@router.get("/ready")
def readiness(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {"ready": True, "service": settings.APP_NAME}
