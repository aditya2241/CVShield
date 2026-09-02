from pydantic import BaseModel, Field, model_validator

class VerifyHashRequest(BaseModel):
    expected_hash: str = Field(min_length=64, max_length=64)

class RiskRequest(BaseModel):
    dataset_integrity: bool = True
    model_integrity: bool = True
    inference_integrity: bool = True
    anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0)
    metadata_anomaly: bool = False
    provenance_verified: bool = True
    distribution_shift: float = Field(default=0.0, ge=0.0, le=1.0)
