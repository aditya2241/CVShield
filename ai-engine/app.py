from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from risk_engine import AnomalyEngine

app = FastAPI(title="TrustGuard AI Engine")
engine = AnomalyEngine()

class Features(BaseModel):
    features: list[list[float]]

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.post("/train")
def train(data: Features):
    engine.fit(data.features)
    return {"status": "trained", "samples": len(data.features)}

@app.post("/score")
def score(data: Features):
    try:
        return {"results": engine.score(data.features)}
    except RuntimeError as exc:
        raise HTTPException(409, str(exc))
