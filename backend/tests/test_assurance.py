from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_root_capabilities():
    response = client.get("/")
    assert response.status_code == 200
    assert "inference-provenance" in response.json()["capabilities"]


def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["database"] == "connected"


def test_safe_scan():
    response = client.post(
        "/api/integrity/scan",
        files={"file": ("clean_demo.txt", b"ordinary dataset sample\n1,2,3\n4,5,6", "text/plain")},
        data={"contributor": "demo-contributor"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert len(payload["sha256"]) == 64
    assert payload["analysis"]["execution_performed"] is False
    assert "risk" in payload["analysis"]


def test_model_registration():
    response = client.post(
        "/api/models/register",
        files={"file": ("demo.onnx", b"PK" + b"model" * 100, "application/octet-stream")},
        data={"contributor": "model-team"},
    )
    assert response.status_code == 200
    assert len(response.json()["sha256"]) == 64


def test_inference_provenance_roundtrip():
    import hashlib

    input_hash = hashlib.sha256(b"input").hexdigest()
    model_hash = hashlib.sha256(b"model").hexdigest()
    create = client.post(
        "/api/inference/records",
        json={
            "input_sha256": input_hash,
            "model_sha256": model_hash,
            "configuration": {"threshold": 0.5},
            "output": {"class": "vehicle", "confidence": 0.91},
        },
    )
    assert create.status_code == 200
    record_id = create.json()["id"]

    verify = client.post(
        f"/api/inference/records/{record_id}/verify",
        json={
            "configuration": {"threshold": 0.5},
            "output": {"class": "vehicle", "confidence": 0.91},
        },
    )
    assert verify.status_code == 200
    assert verify.json()["valid"] is True
