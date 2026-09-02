from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from app.services.assurance_service import distribution_shift

router = APIRouter(prefix='/assurance', tags=['Assurance Analytics'])

class ShiftRequest(BaseModel):
    baseline: list[float] = Field(min_length=2, max_length=100000)
    current: list[float] = Field(min_length=2, max_length=100000)

@router.post('/distribution-shift')
def shift(data: ShiftRequest):
    try:
        return distribution_shift(data.baseline, data.current)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
