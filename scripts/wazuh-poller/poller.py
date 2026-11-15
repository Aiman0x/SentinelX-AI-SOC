#!/usr/bin/env python3
"""Read-only Wazuh Manager/Indexer poller for SentinelX. Python standard library only."""
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone


def required(name):
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required setting: {name}")
    return value


def env_int(name, default, minimum, maximum):
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


def build_ssl_context():
    ca_file = os.getenv("WAZUH_CA_BUNDLE", "").strip()
    return ssl.create_default_context(cafile=ca_file or None)


def require_https(name, value):
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RuntimeError(f"{name} must be a clean HTTPS base URL")
    return value.rstrip("/")


def request_json(url, *, method="GET", headers=None, body=None, context=None, timeout=20):
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, context=context, timeout=timeout) as response:
            payload = response.read(8 * 1024 * 1024)
            if response.status < 200 or response.status >= 300:
                raise RuntimeError(f"HTTP {response.status} from configured endpoint")
            return json.loads(payload.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # Do not print response bodies: they can contain sensitive server details.
        raise RuntimeError(f"HTTP {exc.code} from configured endpoint") from None
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach configured endpoint: {exc.reason}") from None


def manager_token(base, username, password, context):
    raw = (username + ":" + password).encode("utf-8")
    headers = {
        "Authorization": "Basic " + base64.b64encode(raw).decode("ascii"),
        "Accept": "application/json",
    }
    result = request_json(
        base.rstrip("/") + "/security/user/authenticate",
        method="POST",
        headers=headers,
        context=context,
    )
    token = (((result.get("data") or {}).get("token")) if isinstance(result, dict) else None)
    if not token:
        raise RuntimeError("Wazuh Manager authentication returned no token")
    return token


def get_agent_count(base, token, context):
    result = request_json(
        base.rstrip("/") + "/agents?limit=1&offset=0",
        headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
        context=context,
    )
    data = result.get("data", {}) if isinstance(result, dict) else {}
    return int(data.get("total_affected_items", 0))


def severity_from_level(value):
    try:
        level = int(value)
    except (TypeError, ValueError):
        return "unknown"
    if level >= 12:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    if level >= 4:
        return "low"
    return "info"


def normalize_alert(hit):
    source = hit.get("_source") or {}
    rule = source.get("rule") or {}
    agent = source.get("agent") or {}
    data = source.get("data") or {}
    safe_data = {key: data[key] for key in ("srcip", "dstip", "srcport", "dstport", "protocol", "srcuser", "dstuser", "user", "url", "domain", "hostname", "file", "md5", "sha1", "sha256") if key in data}
    event_id = str(hit.get("_index", "wazuh-alerts") + ":" + hit.get("_id", ""))
    description = str(rule.get("description") or "Wazuh alert")
    timestamp = source.get("@timestamp") or source.get("timestamp")
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()
    return {
        "eventId": event_id,
        "timestamp": timestamp,
        "eventType": description[:160],
        "severity": severity_from_level(rule.get("level")),
        "message": description,
        "host": agent.get("name") or agent.get("id") or "Wazuh Manager",
        "sourceIp": safe_data.get("srcip"),
        "destinationIp": safe_data.get("dstip"),
        "username": safe_data.get("dstuser") or safe_data.get("srcuser") or safe_data.get("user"),
        "sourceIntegration": "wazuh",
        "dataOrigin": "WAZUH_INDEXER",
        "eventData": {
            "rule": rule,
            "agent": agent,
            "manager": source.get("manager"),
            "data": safe_data,
            "location": source.get("location"),
            "decoder": source.get("decoder"),
            "wazuh_index": hit.get("_index"),
            "wazuh_document_id": hit.get("_id"),
        },
    }


def main():
    gateway = require_https("SENTINELX_API_URL", required("SENTINELX_API_URL"))
    collector_token = required("SENTINELX_COLLECTOR_TOKEN")
    manager_url = require_https("WAZUH_MANAGER_URL", os.getenv("WAZUH_MANAGER_URL", "https://127.0.0.1:55000"))
    indexer_url = require_https("WAZUH_INDEXER_URL", os.getenv("WAZUH_INDEXER_URL", "https://127.0.0.1:9200"))
    manager_user = required("WAZUH_API_USER")
    manager_password = required("WAZUH_API_PASSWORD")
    indexer_user = required("WAZUH_INDEXER_USER")
    indexer_password = required("WAZUH_INDEXER_PASSWORD")
    lookback = env_int("WAZUH_LOOKBACK_MINUTES", 5, 1, 60)
    batch_size = env_int("WAZUH_BATCH_SIZE", 200, 1, 500)
    context = build_ssl_context()

    token = manager_token(manager_url, manager_user, manager_password, context)
    agent_count = get_agent_count(manager_url, token, context)

    basic = base64.b64encode((indexer_user + ":" + indexer_password).encode("utf-8")).decode("ascii")
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=lookback)
    query = {
        "size": batch_size,
        "track_total_hits": True,
        "sort": [{"timestamp": {"order": "asc"}}],
        "query": {"range": {"timestamp": {"gte": start.isoformat(), "lte": now.isoformat()}}},
    }
    result = request_json(
        indexer_url + "/wazuh-alerts-*/_search",
        method="POST",
        headers={
            "Authorization": "Basic " + basic,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        body=query,
        context=context,
    )
    hits_obj = (result.get("hits") or {}) if isinstance(result, dict) else {}
    hits = hits_obj.get("hits") or []
    events = [normalize_alert(hit) for hit in hits if isinstance(hit, dict)]

    accepted = 0
    for offset in range(0, len(events), 50):
        batch = events[offset:offset + 50]
        response = request_json(
            gateway + "/api/collector/events",
            method="POST",
            headers={
                "Authorization": "Bearer " + collector_token,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            body={"integrationId": "wazuh", "events": batch},
            context=context,
        )
        accepted += int(response.get("accepted", 0))

    heartbeat = request_json(
        gateway + "/api/collector/heartbeat",
        method="POST",
        headers={
            "Authorization": "Bearer " + collector_token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        body={
            "observedAt": now.isoformat(),
            "results": [{
                "integrationId": "wazuh",
                "status": "healthy",
                "checks": [
                    {"name": "manager_api", "status": "pass", "detail": "Authenticated; agent inventory available"},
                    {"name": "indexer_alert_search", "status": "pass", "detail": "Recent alert search completed"},
                    {"name": "sentinelx_ingest", "status": "pass", "detail": "Alert batch forwarded to SentinelX"}
                ],
                "version": "wazuh-poller/1.0",
                "metrics": {"agentCount": agent_count, "alertsMatched": len(hits), "alertsSubmitted": accepted}
            }]
        },
        context=context,
    )

    total = hits_obj.get("total", 0)
    if isinstance(total, dict):
        total = total.get("value", 0)
    print(json.dumps({
        "status": "ok",
        "agentCount": agent_count,
        "alertsMatched": int(total or 0),
        "alertsSubmitted": accepted,
        "heartbeat": heartbeat.get("accepted", []),
        "windowMinutes": lookback,
        "checkedAt": now.isoformat(),
    }))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"status": "error", "error": str(exc)}), file=sys.stderr)
        sys.exit(1)
