# TrustGuard AI — Backend Architecture

TrustGuard is an evidence-assurance prototype for SIH26228. The backend deliberately performs **non-executing** artifact analysis.

## Assurance layers

1. **Dataset/evidence integrity**
   - Streaming upload to disk (bounded memory per request).
   - SHA-256 fingerprint.
   - Exact-fingerprint duplicate check.
   - Filename/MIME/header/content observations.
   - Lightweight CSV/JSON/COCO-style/YOLO-label recognition.
   - Optional reference SHA-256 verification.
   - Contributor recorded in the audit event.

2. **Model assurance**
   - `/api/models/register` fingerprints ONNX/PyTorch/TorchScript-style artifacts.
   - No model deserialization or execution.
   - Basic header/format observations.
   - Registry and audit trail.

3. **Inference provenance**
   - `/api/inference/records` binds input hash + model hash + configuration hash + output hash.
   - A provenance digest and HMAC signature are stored.
   - `/api/inference/records/{id}/verify` detects changes to configuration/output.

4. **Risk engine**
   - Explainable, deterministic score from integrity, anomaly, metadata, provenance and distribution-shift signals.
   - Returns score, severity, factors, confidence and recommended action.

5. **Tamper-evident audit**
   - Hash-chained events.
   - Concurrent append operations are serialized: SQLite uses `BEGIN IMMEDIATE`; PostgreSQL uses a transaction advisory lock.

## Concurrency

For local development, SQLite is configured with WAL mode, a busy timeout and foreign keys. This is suitable for a small demo workload.

For a public multi-user deployment, use **PostgreSQL** and run multiple Uvicorn workers. The SQLAlchemy engine uses a connection pool for non-SQLite databases.

Example production start command:

```bash
uvicorn app.main:app --host 0.0.0.0 --port $PORT --workers 4
```

Do not use `--reload` in production.
