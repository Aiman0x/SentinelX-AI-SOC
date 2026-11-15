#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path

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
