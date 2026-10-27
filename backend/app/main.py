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
        records = body
    elif isinstance(body, dict):
        records = body.get("data", body.get("items", body.get("records")))
        if not isinstance(records, list):
            raise HTTPException(status_code=502, detail={"code": "INVALID_BRIDGE_SCHEMA", "message": "Expected a JSON array or a data/items/records array."})
    else:
        raise HTTPException(status_code=502, detail={"code": "INVALID_BRIDGE_SCHEMA", "message": "Expected a JSON array or a data/items/records array."})
    return [_normalize_record(resource, record) for record in records]


def _cell_values(record: dict[str, Any]) -> dict[str, Any]:
    cells = record.get("cells", {})
    values: dict[str, Any] = {}
    if isinstance(cells, dict):
        for key, cell in cells.items():
            if isinstance(cell, dict):
                name = cell.get("fieldName") or cell.get("name") or key
                values[str(name)] = cell.get("value")
            else:
                values[str(key)] = cell
    # Some webhook versions may already return a plain object keyed by column names.
    for key, value in record.items():
        if key not in {"cells", "id", "created", "updated"} and key not in values:
            values[key] = value
    values["_record_id"] = record.get("id")
    values["_record_created"] = record.get("created")
    values["_record_updated"] = record.get("updated")
    return values


def _as_list(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        try:
            parsed = __import__("json").loads(value)
            if isinstance(parsed, list):
                return [str(item) for item in parsed]
        except (ValueError, TypeError):
            pass
        return [part.strip() for part in value.replace("\\n", ",").split(",") if part.strip()]
    return [str(value)]


def _severity(value: Any) -> str:
    text = str(value or "low").strip().lower()
    if text in {"critical", "high", "medium", "low"}:
        return text
    if text in {"informational", "info", "unclassified"}:
        return "low"
    return "low"


def _normalize_record(resource: str, record: dict[str, Any]) -> dict[str, Any]:
    row = _cell_values(record)
    if resource == "alerts":
        evidence = _as_list(row.get("evidence_event_ids"))
        raw_status = str(row.get("detection_status") or "new").lower()
        status = "resolved" if raw_status in {"resolved", "closed", "suppressed"} else ("investigating" if raw_status in {"investigating", "triaged", "in progress"} else "open")
        return {
            "id": str(row.get("finding_id") or row.get("finding_key") or row.get("_record_id") or "unknown-finding"),
            "eventId": str(evidence[0] if evidence else (row.get("finding_key") or row.get("finding_id") or "")),
            "ruleName": str(row.get("rule_name") or row.get("rule_id") or "Detection finding"),
            "severity": _severity(row.get("severity")),
            "source": "ActivePieces detection finding",
            "asset": str(row.get("host") or "Unknown asset"),
            "sourceIp": str(row.get("source_ips") or ""),
            "timestamp": str(row.get("detected_at") or row.get("_record_created") or ""),
            "status": status,
            "summary": str(row.get("rationale") or "Finding record received; additional investigation context may be pending."),
            "rawEvent": {k: v for k, v in row.items() if not k.startswith("_") and isinstance(v, (str, int, float, bool))},
            "evidence": evidence,
            "relatedAlertIds": _as_list(row.get("related_case_ids")),
            "mitre": [],
            "nextSteps": [],
            **({"caseId": str(row["case_id"])} if row.get("case_id") else {}),
        }
    if resource == "cases":
        raw_status = str(row.get("Status") or row.get("status") or "New").strip().lower()
        status = {"new": "open", "triaged": "investigating", "escalated": "contained", "closed": "closed", "resolved": "resolved", "investigating": "investigating", "open": "open"}.get(raw_status, "open")
        assets = _as_list(row.get("Asset ID") or row.get("Asset Name") or row.get("host"))
        evidence = _as_list(row.get("Raw Evidence") or row.get("Evidence Timeline"))
        recommended = _as_list(row.get("Recommended Actions"))
        created_at = str(row.get("Created At") or row.get("created_at") or row.get("_record_created") or "")
        return {
            "id": str(row.get("Case ID") or row.get("case_id") or row.get("_record_id") or "unknown-case"),
            "title": str(row.get("Case Title") or row.get("case_title") or "Untitled case"),
            "severity": _severity(row.get("Severity") or row.get("severity")),
            "status": status,
            "assignee": str(row.get("Assignee") or row.get("assignee") or "Unassigned"),
            "assets": assets,
            "createdAt": created_at,
            "updatedAt": str(row.get("Updated At") or row.get("updated_at") or row.get("_record_updated") or created_at),
            "overview": str(row.get("AI Analysis") or row.get("Raw Evidence") or row.get("overview") or "No case summary is recorded."),
            "notes": [],
            "evidence": evidence,
            "alertIds": _as_list(row.get("Source Event ID") or row.get("event_id")),
            "timeline": [],
            "recommended": recommended,
        }
    if resource == "assets":
        raw_type = str(row.get("Asset Type") or "").lower()
        asset_type = "Server" if "server" in raw_type else ("Workstation" if "endpoint" in raw_type or "workstation" in raw_type else ("Domain" if "domain" in raw_type else ("Network device" if "network" in raw_type else "Cloud service")))
        raw_monitoring = str(row.get("Monitoring Status") or "").lower()
        monitoring = "verified" if raw_monitoring == "connected" and row.get("Last Verified") else ("stale" if raw_monitoring == "degraded" else ("unmonitored" if raw_monitoring in {"not connected", "retired"} else "registered"))
        return {
            "id": str(row.get("Asset ID") or row.get("_record_id") or "unknown-asset"),
            "name": str(row.get("Asset Name") or "Unnamed asset"),
            "host": str(row.get("Hostname / Domain / IP") or row.get("Asset Name") or ""),
            "ip": str(row.get("IP") or ""),
            "os": str(row.get("Operating System") or ""),
            "type": asset_type,
            "criticality": _severity(row.get("Criticality")),
            "monitoring": monitoring,
            "method": str(row.get("Telemetry Source") or "None"),
            **({"lastEvent": str(row["Last Verified"])} if row.get("Last Verified") else {}),
            "addedBy": "user",
        }
    if resource == "rules":
        raw_status = str(row.get("Status") or "").lower()
        status = "enabled" if raw_status == "enabled" else ("disabled" if raw_status == "disabled" else "draft")
        raw_maturity = str(row.get("Rule Maturity") or "")
        maturity = "validated" if raw_maturity.startswith("4") or raw_maturity.lower() == "validated" else ("in_testing" if raw_maturity.startswith(("2", "3")) else "unvalidated")
        return {
            "id": str(row.get("Rule ID") or row.get("_record_id") or "unknown-rule"),
            "name": str(row.get("Rule Name") or "Unnamed rule"),
            "description": str(row.get("Description") or ""),
            "category": str(row.get("Category") or "Other"),
            "severity": _severity(row.get("Severity")),
            "source": str(row.get("Required Data Source") or ""),
            "mitre": _as_list(row.get("MITRE Technique")),
            "status": status,
            **({"lastTested": str(row["Last Tested"])} if row.get("Last Tested") else {}),
            "maturity": maturity,
            "requiredEvidence": _as_list(row.get("Required Evidence")),
            "logic": str(row.get("Detection Logic") or ""),
            "response": [],
        }
    if resource == "integrations":
        raw_status = str(row.get("Connection Status") or "").upper()
        verified = raw_status == "CONNECTED" and bool(row.get("Last Health Check"))
        state = "connected" if verified else ("error" if raw_status in {"FAILED", "DEGRADED"} else ("not_configured" if raw_status == "NOT CONFIGURED" else "disconnected"))
        category_raw = str(row.get("Category") or "").lower()
        category = "Endpoint" if "endpoint" in category_raw else ("Network" if "network" in category_raw else ("Orchestration" if "orchestration" in category_raw else ("Malware" if "malware" in category_raw else "SIEM")))
        return {
            "id": str(row.get("Integration ID") or row.get("_record_id") or "unknown-integration"),
            "name": str(row.get("Integration Name") or "Unnamed integration"),
            "purpose": str(row.get("Supported Tool Names") or row.get("Category") or ""),
            "category": category,
            "state": state,
            "configured": raw_status not in {"", "NOT CONFIGURED", "SIMULATED ONLY"},
            "verified": verified,
            **({"lastHealthCheck": str(row["Last Health Check"])} if row.get("Last Health Check") else {}),
            "fields": [],
        }
    if resource == "audit":
        outcome = str(row.get("Outcome") or "").lower()
        result = "failure" if outcome == "failure" else ("denied" if outcome == "blocked" else "success")
        action = str(row.get("Event Type") or "Audit event")
        action_lower = action.lower()
        action_type = "create" if "created" in action_lower or "received" in action_lower else ("update" if "updated" in action_lower or "decision" in action_lower else ("response" if "action" in action_lower else ("auth" if "auth" in action_lower else "view")))
        actor_type = "user" if "human" in str(row.get("Actor Type") or "").lower() or "analyst" in str(row.get("Actor Type") or "").lower() else "service"
        return {
            "id": str(row.get("Audit ID") or row.get("_record_id") or "unknown-audit"),
            "time": str(row.get("Timestamp") or row.get("_record_created") or ""),
            "actor": str(row.get("Actor") or "Unknown actor"),
            "actorType": actor_type,
            "action": action,
            "actionType": action_type,
            "target": str(row.get("Case ID") or row.get("Evidence Reference") or ""),
            "result": result,
            "source": "SentinelX Audit Logs",
        }
    return {**{k: v for k, v in row.items() if not k.startswith("_")}, "recordId": row.get("_record_id")}


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
