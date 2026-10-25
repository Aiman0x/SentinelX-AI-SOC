import type { Integration } from '../types/integration';
import { minutesAgo } from '../utils/formatDate';

/**
 * DEMO DATA — sample integration states for UI demonstration.
 * No entry is "connected": that value may only be produced by a real backend health check.
 * Secret fields (secret: true) are never persisted in the browser.
 */
export const demoIntegrations: Integration[] = [
  {
    id: 'activepieces', name: 'ActivePieces', category: 'Orchestration',
    purpose: 'Workflow orchestration: ingestion, validation, case creation and response playbooks.',
    state: 'demo', configured: false, verified: false,
    fields: [
      { key: 'baseUrl', label: 'ActivePieces base URL', placeholder: 'https://activepieces.example.com' },
      { key: 'webhookPath', label: 'Ingest webhook path', placeholder: '/api/v1/webhooks/<flow-id>' },
      { key: 'webhookSecret', label: 'Webhook secret', placeholder: '••••••••', secret: true, help: 'Stored server-side only.' },
    ],
  },
  {
    id: 'wazuh', name: 'Wazuh', category: 'SIEM',
    purpose: 'Host-based detection, log analysis and file-integrity monitoring.',
    state: 'not_configured', configured: false, verified: false,
    fields: [
      { key: 'apiUrl', label: 'Wazuh API URL', placeholder: 'https://wazuh.example.com:55000' },
      { key: 'apiUser', label: 'API user', placeholder: 'sentinelx-readonly' },
      { key: 'apiPassword', label: 'API password', placeholder: '••••••••', secret: true },
    ],
  },
  {
    id: 'sysmon', name: 'Windows Sysmon', category: 'Endpoint',
    purpose: 'Detailed Windows process, network and registry telemetry.',
    state: 'demo', configured: false, verified: false,
    fields: [
      { key: 'collector', label: 'Log collector (via Wazuh / WEF)', placeholder: 'wazuh | wef' },
      { key: 'configVersion', label: 'Sysmon config version', placeholder: 'e.g. v14.16 + modular rules' },
    ],
  },
  {
    id: 'clamav', name: 'ClamAV', category: 'Malware',
    purpose: 'Open-source antivirus scanning for files and attachments.',
    state: 'disconnected', configured: true, verified: false, lastHealthCheck: minutesAgo(5200),
    fields: [
      { key: 'host', label: 'clamd host', placeholder: '127.0.0.1' },
      { key: 'port', label: 'clamd port', placeholder: '3310' },
    ],
  },
  {
    id: 'yara', name: 'YARA', category: 'Malware',
    purpose: 'Pattern-based malware classification using curated rule sets.',
    state: 'error', configured: true, verified: false, lastHealthCheck: minutesAgo(1900),
    fields: [
      { key: 'rulesPath', label: 'Rules directory (server path)', placeholder: '/opt/sentinelx/yara-rules' },
    ],
  },
  {
    id: 'suricata', name: 'Suricata', category: 'Network',
    purpose: 'Network IDS/IPS alerts and protocol metadata (eve.json).',
    state: 'not_configured', configured: false, verified: false,
    fields: [
      { key: 'eveLog', label: 'eve.json source', placeholder: 'syslog | file | Wazuh' },
      { key: 'sensor', label: 'Sensor name', placeholder: 'sensor-01' },
    ],
  },
  {
    id: 'zeek', name: 'Zeek', category: 'Network',
    purpose: 'Network traffic analysis logs (conn, dns, http, ssl).',
    state: 'not_configured', configured: false, verified: false,
    fields: [
      { key: 'logPath', label: 'Log source', placeholder: 'file | Kafka | Wazuh' },
      { key: 'sensor', label: 'Sensor name', placeholder: 'sensor-01' },
    ],
  },
];
