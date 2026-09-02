# CVSHIELD

A defensive computer-vision integrity assurance platform for checking datasets, model artifacts, inference provenance, and audit evidence.

## Project structure

- `frontend/` — React + Vite security console
- `backend/` — FastAPI API, integrity analysis, hashing, provenance, audit trail, risk scoring
- `ai-engine/` — local risk-analysis components
- `database/` — database schema
- `security/` — hashing/integrity helpers
- `demo_samples/` — safe non-executing demo files
- `docs/` — architecture and demo flow

## Run locally

### Backend
```bash
cd backend
python -m venv .venv
# Windows
.venv\\Scripts\\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

Set `VITE_API_URL` in `frontend/.env` to your backend URL when frontend and backend run separately.

## Render

Backend Web Service:
- Root Directory: `backend`
- Build: `pip install -r requirements.txt`
- Start: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`

Frontend Static Site:
- Root Directory: `frontend`
- Build: `npm install && npm run build`
- Publish Directory: `dist`
- Environment: `VITE_API_URL=<your backend URL>`

## Safety

The platform performs non-executing defensive analysis. It does not execute uploaded files or remote content.
