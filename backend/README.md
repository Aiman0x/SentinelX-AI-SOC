# SentinelX Backend — Phase 1 Bridge

This directory contains a FastAPI server-side bridge for the existing SentinelX GUI and ActivePieces project.

## Implemented API surface

- `GET /health` — backend health.
- `GET /api/status` — per-feature connection/configuration status.
- `GET /api/capabilities` — implemented versus pending features.
- `GET /api/alerts`, `/api/cases`, `/api/assets`, `/api/rules`, `/api/integrations`, `/api/audit`, `/api/investigations`, `/api/evidence` — stable read API contract. Each route returns HTTP 503 with `FEATURE_PENDING` until its dedicated read-only ActivePieces webhook is configured.
- `POST /api/telemetry` — validates a bounded JSON payload and forwards it server-side to the existing ActivePieces telemetry receiver when its URL and secret are configured.

This source does not claim the read APIs are live yet. Existing ActivePieces Tables must be exposed through dedicated authenticated read-only webhook flows or another verified supported server-side API. Do not guess undocumented ActivePieces Tables URLs.

## Local Windows setup (PyCharm terminal)

From this `backend` directory:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Then visit:
- `http://127.0.0.1:8000/health`
- `http://127.0.0.1:8000/docs`
- `http://127.0.0.1:8000/api/status`

Edit `backend/.env` locally only. Never commit it. Never put ActivePieces secrets into frontend `VITE_*` variables.

## ActivePieces configuration still required

1. Copy the real URL for the existing enabled flow `SX Phase 3 - Receive Normalized Windows Telemetry` from ActivePieces into `AP_TELEMETRY_WEBHOOK_URL`.
2. Configure its matching header name and secret on the backend host. The secret must match the ActivePieces trigger configuration; if it is rotated in ActivePieces, update the backend secret too.
3. Create one authenticated, read-only webhook per resource for the existing tables. Each flow should use Tables → Find Records on the relevant existing table, apply a reasonable limit, and return JSON in `{"data":[...]}` form. Set a long random shared secret in the webhook's header authentication and `AP_BRIDGE_SECRET`.
4. Set the corresponding `AP_*_READ_URL` variables only after each flow is published and its response verified.

The backend intentionally does not mutate cases, notes, rules, approvals, or response playbooks yet. Those remain Pending; no disruptive actions are executed.

## Frontend connection

Set `VITE_API_BASE_URL` in the frontend's local `.env.local` to the backend base URL (for local development: `http://127.0.0.1:8000`). For the published GitHub Pages GUI, use a separately hosted HTTPS backend URL. GitHub Pages cannot host this Python server.

## Deployment and security

This starter has no user/session authentication yet and must not be exposed publicly with real security telemetry until that is implemented. CORS is not authentication. Use HTTPS, server-side secrets, a durable host, and review tenant/data isolation before exposing real records.
