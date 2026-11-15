#!/usr/bin/env python3
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import poller


class WazuhPollerTests(unittest.TestCase):
    def test_normalizes_alert_and_preserves_stable_document_id(self):
        event = poller.normalize_alert({
            "_index": "wazuh-alerts-4.x-2026.11.15",
            "_id": "abc123",
            "_source": {
                "timestamp": "2026-11-15T10:00:00.000Z",
                "rule": {"id": "5710", "level": 12, "description": "Multiple failed logins"},
                "agent": {"id": "001", "name": "linux-web-01"},
                "data": {"srcip": "203.0.113.10", "dstuser": "admin"},
                "full_log": "Authentication failed"
            }
        })
        self.assertEqual(event["eventId"], "wazuh-alerts-4.x-2026.11.15:abc123")
        self.assertEqual(event["timestamp"], "2026-11-15T10:00:00.000Z")
        self.assertEqual(event["severity"], "critical")
        self.assertEqual(event["host"], "linux-web-01")
        self.assertEqual(event["sourceIp"], "203.0.113.10")
        self.assertEqual(event["username"], "admin")
        self.assertEqual(event["sourceIntegration"], "wazuh")

    def test_normalizes_raw_windows_archive_event(self):
        event = poller.normalize_archive_event({
            "timestamp": "2026-11-15T15:47:27.618+0000",
            "agent": {"id": "001", "name": "SentinelX-Windows-01"},
            "id": "1794757647.1222373",
            "full_log": "A security-enabled local group membership was enumerated.",
            "decoder": {"name": "windows_eventchannel"},
            "data": {"win": {"system": {
                "eventID": "4799",
                "eventRecordID": "468021",
                "channel": "Security",
                "computer": "DESKTOP-GCH1G1S",
                "providerName": "Microsoft-Windows-Security-Auditing",
                "message": "A security-enabled local group membership was enumerated."
            }, "eventdata": {"targetUserName": "Administrators"}}},
            "location": "EventChannel"
        })
        self.assertEqual(event["eventId"], "wazuh-archive:001:468021")
        self.assertEqual(event["eventType"], "windows_event_4799")
        self.assertEqual(event["host"], "DESKTOP-GCH1G1S")
        self.assertEqual(event["dataOrigin"], "WAZUH_ARCHIVE")
        self.assertEqual(event["eventData"]["EventID"], "4799")
        self.assertEqual(event["eventData"]["eventdata"]["targetUserName"], "Administrators")

    def test_archive_reader_starts_at_eof_then_reads_only_new_complete_lines(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "ossec-archive-15.json"
            state = root / "state.json"
            archive.write_text('{"timestamp":"2026-11-15T15:00:00Z","id":"old"}\n', encoding="utf-8")
            with patch.dict(os.environ, {
                "WAZUH_ARCHIVE_GLOB": str(root / "ossec-archive-*.json"),
                "WAZUH_ARCHIVE_STATE_FILE": str(state),
            }):
                initial, count, baseline = poller.read_new_archive_events(20)
                self.assertEqual(initial, [])
                self.assertEqual(count, 0)
                archive.open("a", encoding="utf-8").write(json.dumps({
                    "timestamp": "2026-11-15T15:01:00Z",
                    "agent": {"id": "001", "name": "win-01"},
                    "data": {"win": {"system": {"eventID": "4625", "eventRecordID": "9001", "computer": "win-01"}}}
                }) + "\n")
                events, count, updated = poller.read_new_archive_events(20)
                self.assertEqual(count, 1)
                self.assertEqual(events[0]["eventId"], "wazuh-archive:001:9001")
                poller.save_archive_state(state, updated)
                again, count, _ = poller.read_new_archive_events(20)
                self.assertEqual(again, [])
                self.assertEqual(count, 0)

    def test_maps_wazuh_severity_levels(self):
        self.assertEqual(poller.severity_from_level(15), "critical")
        self.assertEqual(poller.severity_from_level(10), "high")
        self.assertEqual(poller.severity_from_level(7), "medium")
        self.assertEqual(poller.severity_from_level(4), "low")
        self.assertEqual(poller.severity_from_level(2), "info")

    def test_requires_https_for_all_service_urls(self):
        self.assertEqual(poller.require_https("gateway", "https://example.com"), "https://example.com")
        with self.assertRaises(RuntimeError):
            poller.require_https("manager", "http://127.0.0.1:55000")

    def test_rejects_credentials_embedded_in_url(self):
        with self.assertRaises(RuntimeError):
            poller.require_https("indexer", "https://user:pass@example.com:9200")


if __name__ == "__main__":
    unittest.main()
