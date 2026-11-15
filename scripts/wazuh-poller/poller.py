#!/usr/bin/env python3
"""Read-only Wazuh Manager/Indexer poller plus incremental raw archive forwarder."""
import base64
import glob
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path


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
    # Keep the operating system trust store for the public SentinelX HTTPS
    # gateway, then add the private Wazuh CA for the local Manager/Indexer.
    context = ssl.create_default_context()
    ca_file = os.getenv("WAZUH_CA_BUNDLE", "").strip()
    if ca_file:
        context.load_verify_locations(cafile=ca_file)
    return context


def require_https(name, value):
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise RuntimeError(f"{name} must be a clean HTTPS base URL")
    return value.rstrip("/")


def request_json(url, *, method="GET", headers=None, body=None, context=None, timeout=20):
    data = None if body is None else json.dumps(body).encode("utf-8")
    request_headers = dict(headers or {})
    # Cloudflare blocks urllib default signatures on workers.dev hostnames.
    # Identify this legitimate application client without impersonating a browser.
    request_headers.setdefault("User-Agent", "SentinelX-Wazuh-Poller/1.0")
    req = urllib.request.Request(url, data=data, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(req, context=context, timeout=timeout) as response:
            payload = response.read(8 * 1024 * 1024)
            if response.status < 200 or response.status >= 300:
                raise RuntimeError(f"HTTP {response.status} from configured endpoint")
            return json.loads(payload.decode("utf-8"))
    except urllib.error.HTTPError as exc:
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
        "dataOrigin": "WAZUH_INDEXER_ALERT",
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


def normalize_archive_event(record):
    """Keep raw Windows/Linux event context while making it safe for SentinelX ingestion."""
    data = record.get("data") or {}
    win = data.get("win") or {}
    system = win.get("system") or {}
    eventdata = win.get("eventdata") or {}
    agent = record.get("agent") or {}
    event_number = str(system.get("eventID") or system.get("eventId") or "unknown")
    record_number = str(system.get("eventRecordID") or "")
    timestamp = record.get("timestamp") or system.get("systemTime") or datetime.now(timezone.utc).isoformat()
    agent_id = str(agent.get("id") or "manager")
    stable_id = "wazuh-archive:" + agent_id + ":" + (record_number or str(record.get("id") or timestamp))
    message = str(system.get("message") or record.get("full_log") or ("Wazuh raw event " + event_number))
    host = str(system.get("computer") or agent.get("name") or agent_id)
    event_data = dict(eventdata) if isinstance(eventdata, dict) else {}
    event_data.update({
        "EventID": event_number,
        "eventRecordID": record_number or None,
        "channel": system.get("channel"),
        "providerName": system.get("providerName"),
        "severityValue": system.get("severityValue"),
        "IpAddress": eventdata.get("ipAddress") or eventdata.get("IpAddress"),
        "SourceAddress": eventdata.get("sourceAddress") or eventdata.get("SourceAddress"),
        "DestinationIp": eventdata.get("destinationIp") or eventdata.get("DestinationIp"),
        "eventdata": eventdata,
        "agent": agent,
        "manager": record.get("manager"),
        "decoder": record.get("decoder"),
        "location": record.get("location"),
        "fullLog": record.get("full_log"),
    })
    return {
        "eventId": stable_id,
        "timestamp": timestamp,
        "eventType": "windows_event_" + event_number if event_number != "unknown" else "wazuh_raw_event",
        "severity": "info",
        "message": message[:4000],
        "host": host,
        "sourceIntegration": "wazuh_raw_archive",
        "dataOrigin": "WAZUH_ARCHIVE",
        "eventData": event_data,
    }


def archive_state_path():
    return Path(os.getenv("WAZUH_ARCHIVE_STATE_FILE", "/var/lib/sentinelx-wazuh-poller/archive-offsets.json"))


def archive_paths():
    pattern = os.getenv("WAZUH_ARCHIVE_GLOB", "/var/ossec/logs/archives/*/*/ossec-archive-*.json")
    return sorted(glob.glob(pattern), key=lambda name: (os.path.getmtime(name), name))


def load_archive_state(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, dict) and isinstance(value.get("files"), dict):
            return value
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        raise RuntimeError("Wazuh archive offset state is unreadable; preserve the file and inspect it before resetting.")
    return {"initialized": False, "files": {}}


def save_archive_state(path, state):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def read_new_archive_events(max_events):
    """Read only appended complete JSON lines; first run safely starts at current EOF."""
    state_path = archive_state_path()
    state = load_archive_state(state_path)
    paths = archive_paths()
    if not state.get("initialized"):
        for name in paths:
            stat = os.stat(name)
            state["files"][name] = {"inode": stat.st_ino, "offset": stat.st_size}
        state["initialized"] = True
        save_archive_state(state_path, state)
        return [], 0, state

    events = []
    offsets_changed = False
    for name in paths:
        if len(events) >= max_events:
            break
        try:
            stat = os.stat(name)
        except FileNotFoundError:
            continue
        previous = state["files"].get(name) or {}
        offset = int(previous.get("offset", 0))
        if previous.get("inode") != stat.st_ino or offset > stat.st_size:
            offset = 0
        try:
            with open(name, "rb") as stream:
                stream.seek(offset)
                while len(events) < max_events:
                    line = stream.readline()
                    if not line:
                        break
                    if not line.endswith(b"\n"):
                        stream.seek(-len(line), os.SEEK_CUR)
                        break
                    offset = stream.tell()
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    if isinstance(record, dict):
                        events.append(normalize_archive_event(record))
                state["files"][name] = {"inode": stat.st_ino, "offset": offset}
                offsets_changed = True
        except OSError as exc:
            raise RuntimeError("Cannot read Wazuh archive file; check sentinelx-poller group access.") from exc
    return events, len(events), state


def send_event_batches(gateway, collector_token, integration_id, events, context):
    accepted = 0
    for offset in range(0, len(events), 25):
        batch = events[offset:offset + 25]
        response = request_json(
            gateway + "/api/collector/events",
            method="POST",
            headers={
                "Authorization": "Bearer " + collector_token,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            body={"integrationId": integration_id, "events": batch},
            context=context,
        )
        accepted += int(response.get("accepted", 0))
    return accepted


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
    archive_max = env_int("WAZUH_ARCHIVE_MAX_EVENTS", 200, 1, 500)
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
    alerts = [normalize_alert(hit) for hit in hits if isinstance(hit, dict)]
    alerts_submitted = send_event_batches(gateway, collector_token, "wazuh", alerts, context)

    raw_events, raw_count, archive_state = read_new_archive_events(archive_max)
    raw_submitted = send_event_batches(gateway, collector_token, "wazuh", raw_events, context)
    # Persist offsets only after all raw batches have been accepted. A failed request
    # replays the same lines on the next run; stable event IDs make replay idempotent.
    save_archive_state(archive_state_path(), archive_state)

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
                    {"name": "raw_archive_read", "status": "pass", "detail": str(raw_count) + " new raw events read"},
                    {"name": "sentinelx_ingest", "status": "pass", "detail": "Alert and raw event batches forwarded"}
                ],
                "version": "wazuh-poller/1.1",
                "metrics": {"agentCount": agent_count, "alertsMatched": len(hits), "alertsSubmitted": alerts_submitted, "rawEventsRead": raw_count, "rawEventsSubmitted": raw_submitted}
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
        "alertsSubmitted": alerts_submitted,
        "rawEventsRead": raw_count,
        "rawEventsSubmitted": raw_submitted,
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
