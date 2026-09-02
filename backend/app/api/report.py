from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from app.db import get_db
from app.models.dataset import Dataset
from app.models.model_artifact import ModelArtifact
from app.models.inference import InferenceRecord
from app.services.audit_service import verify_audit_chain

router = APIRouter(prefix='/reports', tags=['Assurance Reports'])

@router.get('/summary')
def summary(db: Session = Depends(get_db)):
    datasets = db.scalars(select(Dataset).order_by(Dataset.id.desc()).limit(100)).all()
    models = db.scalars(select(ModelArtifact).order_by(ModelArtifact.id.desc()).limit(100)).all()
    inferences = db.scalars(select(InferenceRecord).order_by(InferenceRecord.id.desc()).limit(100)).all()
    return {
        'problem_statement': 'SIH26228',
        'generated_from_local_evidence': True,
        'counts': {'datasets': len(datasets), 'models': len(models), 'inference_records': len(inferences)},
        'dataset_status': {'verified': sum(x.integrity_status == 'VERIFIED' for x in datasets), 'review': sum(x.integrity_status == 'REVIEW' for x in datasets)},
        'model_status': {'trusted': sum(x.status == 'TRUSTED' for x in models), 'review': sum(x.status == 'REVIEW' for x in models), 'tampered': sum(x.status == 'TAMPERED' for x in models)},
        'inference_status': {'verified': sum(x.status == 'VERIFIED' for x in inferences), 'tampered': sum(x.status == 'TAMPERED' for x in inferences)},
        'audit_chain_valid': verify_audit_chain(db),
        'limitations': [
            'Behavioural/backdoor analysis is static and non-executing; it is not a proof of model safety.',
            'Distribution shift endpoint uses numeric feature summaries and should be calibrated with operational baseline data.',
        ],
    }
