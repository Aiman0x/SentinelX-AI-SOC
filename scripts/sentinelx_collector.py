#!/usr/bin/env python3
"""SentinelX read-only host collector. Python 3.10+, standard library only."""
from __future__ import annotations
import argparse, json, os, platform, shutil, subprocess, sys, time, urllib.request, urllib.error
from datetime import datetime, timezone
from pathlib import Path

TOOLS = ("sysmon", "clamav", "yara", "suricata", "zeek")
def now(): return datetime.now(timezone.utc).isoformat()
def run(args, timeout=5):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, (p.stdout or p.stderr).strip()[:500]
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""
def recent_file(path):
    try: return max(0, time.time() - Path(path).stat().st_mtime) < 600
    except OSError: return False
def result(tool, status, checks, version=None, metrics=None):
    return {"integrationId": tool, "status": status, "checks": checks, "version": version, "metrics": metrics or {}, "observedAt": now()}
def collect_sysmon():
    if platform.system() != "Windows": return result("sysmon", "unknown", [{"name":"platform","status":"warn","detail":"Sysmon adapter requires Windows."}])
    code, output = run(["powershell", "-NoProfile", "-Command", "Get-Service -Name Sysmon64,Sysmon -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Status"])
    installed = code == 0 and bool(output)
    channel = run(["wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational", "/c:1", "/rd:true", "/f:text"])[0] == 0 if installed else False
    status = "healthy" if installed and channel else "unhealthy" if installed else "not_installed"
    return result("sysmon", status, [{"name":"service","status":"pass" if installed else "fail","detail":"Sysmon service detected." if installed else "Sysmon service not detected."},{"name":"event_channel","status":"pass" if channel else "fail","detail":"Sysmon event channel is readable." if channel else "Sysmon event channel unavailable."}])
def collect_clamav():
    binary = shutil.which("clamscan") or shutil.which("clamdscan")
    if not binary: return result("clamav","not_installed",[{"name":"binary","status":"fail","detail":"clamscan/clamdscan not found in PATH."}])
    code, version = run([binary, "--version"])
    return result("clamav","healthy" if code == 0 else "degraded",[{"name":"version","status":"pass" if code == 0 else "fail","detail":"ClamAV version command completed." if code == 0 else "ClamAV version check failed."}],version)
def collect_yara():
    binary = shutil.which("yara")
    if not binary: return result("yara","not_installed",[{"name":"binary","status":"fail","detail":"YARA executable not found in PATH."}])
    code, version = run([binary, "--version"])
    return result("yara","healthy" if code == 0 else "degraded",[{"name":"version","status":"pass" if code == 0 else "fail","detail":"YARA version command completed." if code == 0 else "YARA version check failed."}],version)
def collect_suricata():
    binary = shutil.which("suricata")
    if not binary: return result("suricata","not_installed",[{"name":"binary","status":"fail","detail":"Suricata executable not found in PATH."}])
    code, version = run([binary, "--build-info"])
    candidates = ["/var/log/suricata/eve.json", "/var/log/suricata/eve.json.1"]
    fresh = any(recent_file(p) for p in candidates)
    return result("suricata","healthy" if code == 0 and fresh else "degraded",[{"name":"binary","status":"pass" if code == 0 else "fail","detail":"Suricata executable responds." if code == 0 else "Suricata check failed."},{"name":"eve_telemetry","status":"pass" if fresh else "warn","detail":"Recent eve.json activity observed." if fresh else "No recent default eve.json activity; configure log path if customized."}],version)
def collect_zeek():
    binary = shutil.which("zeek")
    if not binary: return result("zeek","not_installed",[{"name":"binary","status":"fail","detail":"Zeek executable not found in PATH."}])
    code, version = run([binary, "--version"])
    candidates = ["/opt/zeek/logs/current/conn.log", "/usr/local/zeek/logs/current/conn.log", "/var/log/zeek/current/conn.log"]
    fresh = any(recent_file(p) for p in candidates)
    return result("zeek","healthy" if code == 0 and fresh else "degraded",[{"name":"binary","status":"pass" if code == 0 else "fail","detail":"Zeek executable responds." if code == 0 else "Zeek check failed."},{"name":"conn_telemetry","status":"pass" if fresh else "warn","detail":"Recent conn.log activity observed." if fresh else "No recent default conn.log activity; configure log path if customized."}],version)
ADAPTERS = {"sysmon":collect_sysmon,"clamav":collect_clamav,"yara":collect_yara,"suricata":collect_suricata,"zeek":collect_zeek}
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--url", default=os.getenv("SENTINELX_URL",""))
    parser.add_argument("--token", default=os.getenv("SENTINELX_COLLECTOR_TOKEN",""))
    parser.add_argument("--interval", type=int, default=300)
    parser.add_argument("--once", action="store_true")
    args=parser.parse_args()
    if not args.url.startswith("https://") or not args.token:
        parser.error("Set HTTPS --url and --token (or SENTINELX_URL / SENTINELX_COLLECTOR_TOKEN).")
    endpoint=args.url.rstrip("/")+"/api/collector/heartbeat"
    while True:
        results=[fn() for fn in ADAPTERS.values()]
        payload=json.dumps({"observedAt":now(),"host":platform.node(),"platform":platform.system().lower(),"results":results}).encode()
        req=urllib.request.Request(endpoint,data=payload,headers={"Content-Type":"application/json","Authorization":"Bearer "+args.token,"User-Agent":"SentinelX-Collector/1.0"},method="POST")
        try:
            with urllib.request.urlopen(req,timeout=15) as response:
                if response.status not in (200,201): raise RuntimeError("Gateway returned HTTP "+str(response.status))
                print(now(),"heartbeat accepted:",response.read(2048).decode(errors="replace"))
        except (urllib.error.URLError, TimeoutError, RuntimeError) as exc:
            print(now(),"heartbeat failed:",str(exc),file=sys.stderr)
        if args.once: break
        time.sleep(max(60,args.interval))
if __name__=="__main__": main()
