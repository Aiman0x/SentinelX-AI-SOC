from __future__ import annotations

from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: str = "development"
    frontend_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    request_timeout_seconds: float = 15.0

    ap_telemetry_webhook_url: str = ""
    ap_telemetry_header_name: str = "X-SentinelX-Key"
    ap_telemetry_secret: str = ""

    ap_bridge_header_name: str = "X-SentinelX-Bridge-Key"
    ap_bridge_secret: str = ""
    ap_alerts_read_url: str = ""
    ap_cases_read_url: str = ""
    ap_assets_read_url: str = ""
    ap_rules_read_url: str = ""
    ap_integrations_read_url: str = ""
    ap_audit_read_url: str = ""
    ap_investigations_read_url: str = ""
    ap_evidence_read_url: str = ""


settings = Settings()
app = FastAPI(
    title="SentinelX API",
    version="0.1.0",
    description="Server-side API bridge for the SentinelX GUI and existing ActivePieces workflows.",
)

origins = [value.strip() for value in settings.frontend_origins.split(",") if value.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)


class TelemetryIn(BaseModel):
    event_id: str | None = Field(default=None, max_length=200)
    source_event_id: str | None = Field(default=None, max_length=200)
    event_type: str = Field(min_length=1, max_length=200)
    event_time: str | None = None
    host: str | None = Field(default=None, max_length=255)
    username: str | None = Field(default=None, max_length=255)
    source_ip: str | None = Field(default=None, max_length=100)
    source_integration: str = Field(default="sentinelx-gui", max_length=100)
    data_origin: str = Field(default="SYNTHETIC_TEST", max_length=40)
    event_data: dict[str, Any] = Field(default_factory=dict)


READ_ROUTES = {
    "alerts": ("/api/alerts", "ap_alerts_read_url"),
    "cases": ("/api/cases", "ap_cases_read_url"),
    "assets": ("/api/assets", "ap_assets_read_url"),
    "rules": ("/api/rules", "ap_rules_read_url"),
    "integrations": ("/api/integrations", "ap_integrations_read_url"),
    "audit": ("/api/audit", "ap_audit_read_url"),
    "investigations": ("/api/investigations", "ap_investigations_read_url"),
    "evidence": ("/api/evidence", "ap_evidence_read_url"),
}


def _feature(url: str, secret_required: bool = True) -> dict[str, str]:
    if not url:
        return {"status": "pending", "source": "activepieces", "detail": "Read webhook not configured"}
    if secret_required and not settings.ap_bridge_secret:
        return {"status": "not_configured", "source": "activepieces", "detail": "Server-side bridge secret missing"}
    return {"status": "configured_unverified", "source": "activepieces", "detail": "Configured; live verification pending"}


async def _read_resource(resource: str, url: str, limit: int) -> list[dict[str, Any]]:
    if not url:
        raise HTTPException(
            status_code=503,
            detail={"code": "FEATURE_PENDING", "message": f"{resource} is pending: its read-only ActivePieces bridge is not configured."},
        )
    if not settings.ap_bridge_secret:
        raise HTTPException(status_code=503, detail={"code": "BRIDGE_SECRET_MISSING", "message": "Server-side bridge secret is not configured."})

    headers = {settings.ap_bridge_header_name: settings.ap_bridge_secret}
    try:
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds, follow_redirects=False) as client:
            response = await client.post(url, json={"resource": resource, "limit": max(1, min(limit, 200))}, headers=headers)
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail={"code": "ACTIVEPIECES_TIMEOUT", "message": "ActivePieces read webhook timed out."})
    except httpx.HTTPError:
        raise HTTPException(status_code=502, detail={"code": "ACTIVEPIECES_UNAVAILABLE", "message": "Could not reach the ActivePieces read webhook."})

    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail={"code": "ACTIVEPIECES_ERROR", "message": f"ActivePieces returned HTTP {response.status_code}."})
    try:
        body = response.json()
    except ValueError:
        raise HTTPException(status_code=502, detail={"code": "INVALID_BRIDGE_RESPONSE", "message": "ActivePieces read webhook did not return JSON."})

    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        records = body.get("data", body.get("items", body.get("records")))
        if isinstance(records, list):
            return records
    raise HTTPException(status_code=502, detail={"code": "INVALID_BRIDGE_SCHEMA", "message": "Expected a JSON array or a data/items/records array."})


@app.get("/")
async def root() -> dict[str, str]:
    return {"name": "SentinelX API", "version": "0.1.0", "mode": settings.app_env}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "sentinelx-api", "mode": settings.app_env}


@app.get("/api/status")
async def api_status() -> dict[str, Any]:
    features: dict[str, dict[str, str]] = {}
    for resource, (_, attr) in READ_ROUTES.items():
        features[resource] = _feature(getattr(settings, attr))
    telemetry_ready = bool(settings.ap_telemetry_webhook_url and settings.ap_telemetry_secret)
    features["telemetry_ingestion"] = {
        "status": "configured_unverified" if telemetry_ready else "pending",
        "source": "existing_activepieces_receiver",
        "detail": "Configured; live verification pending" if telemetry_ready else "Existing receiver URL/secret not configured",
    }
    features["playbooks"] = {"status": "pending", "source": "activepieces", "detail": "Execution API not connected; no response actions are run by this API"}
    statuses = {item["status"] for item in features.values()}
    overall = "connected" if statuses == {"connected"} else ("pending" if statuses <= {"pending", "not_configured"} else "partial")
    return {"overall": overall, "features": features}


@app.get("/api/capabilities")
async def capabilities() -> dict[str, Any]:
    return {
        "implemented": ["health", "feature-status", "read-api-contract", "telemetry-submit-proxy"],
        "pending": [
            "published-read-only-activepieces-webhooks",
            "persistent-case-mutations",
            "case-notes-and-status-updates",
            "rule-mutations",
            "authenticated-user-session",
            "production-deployment",
        ],
        "safety": "No containment or disruptive response actions are executed by this API.",
    }


def _register_read_route(resource: str, url_attr: str):
    async def endpoint(limit: int = Query(default=100, ge=1, le=200)):
        return await _read_resource(resource, getattr(settings, url_attr), limit)
    endpoint.__name__ = f"get_{resource}"
    app.get(f"/api/{resource}", name=endpoint.__name__)(endpoint)


for _resource, (_route, _attr) in READ_ROUTES.items():
    _register_read_route(_resource, _attr)


@app.post("/api/telemetry")
async def submit_telemetry(event: TelemetryIn) -> dict[str, Any]:
    if not settings.ap_telemetry_webhook_url or not settings.ap_telemetry_secret:
        raise HTTPException(status_code=503, detail={"code": "INGESTION_PENDING", "message": "The existing ActivePieces telemetry receiver is not configured on this backend."})

    headers = {settings.ap_telemetry_header_name: settings.ap_telemetry_secret}
    try:
        async with httpx.AsyncClient(timeout=settings.request_timeout_seconds, follow_redirects=False) as client:
            response = await client.post(
                settings.ap_telemetry_webhook_url,
                json=event.model_dump(exclude_none=True),
                headers=headers,
            )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail={"code": "ACTIVEPIECES_TIMEOUT", "message": "Telemetry receiver timed out."})
    except httpx.HTTPError:
        raise HTTPException(status_code=502, detail={"code": "ACTIVEPIECES_UNAVAILABLE", "message": "Could not reach the ActivePieces telemetry receiver."})

    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail={"code": "INGESTION_REJECTED", "message": f"ActivePieces receiver returned HTTP {response.status_code}."})
    try:
        body = response.json()
    except ValueError:
        body = {"http_status": response.status_code}
    return {"accepted": True, "source": "activepieces_receiver", "result": body}
