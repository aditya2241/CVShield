from fastapi import APIRouter
from app.schemas.integrity import RiskRequest
from app.services.risk_service import calculate_risk

router = APIRouter(prefix="/risk", tags=["Risk"])

@router.post("/score")
def risk_score(data: RiskRequest):
    return calculate_risk(
        dataset_integrity=data.dataset_integrity,
        model_integrity=data.model_integrity,
        inference_integrity=data.inference_integrity,
        anomaly_score=data.anomaly_score,
        metadata_anomaly=data.metadata_anomaly,
        provenance_verified=data.provenance_verified,
        distribution_shift=data.distribution_shift,
    )
