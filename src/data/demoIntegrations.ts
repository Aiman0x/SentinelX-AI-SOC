import type { Integration } from '../types/integration';

/**
 * Integration catalog. Every tool starts unconfigured; connected state requires a real backend health check.
 * Secret fields (secret: true) are never persisted in the browser.
 */
export const demoIntegrations: Integration[] = [
  {
    id: 'activepieces', name: 'ActivePieces', category: 'Orchestration',
    purpose: 'Workflow orchestration: ingestion, validation, case creation and response playbooks. Gateway connectivity is managed server-side.',
    state: 'demo', configured: false, verified: false,
    fields: [],
  },
  {
    id: 'wazuh', name: 'Wazuh', category: 'SIEM',
    purpose: 'Host-based detection, log analysis and file-integrity monitoring.',
    state: 'not_configured', configured: false, verified: false,
    fields: [
      { key: 'apiUrl', label: 'Wazuh API URL', placeholder: 'https://wazuh.example.com:55000' },
      { key: 'apiUser', label: 'API user', placeholder: 'sentinelx-readonly' },
      { key: 'apiPassword', label: 'API password', placeholder: '••••••••', secret: true },
      { key: 'accessClientId', label: 'Cloudflare Access Client ID (optional)', placeholder: 'Access service token ID', secret: true, help: 'Only if the Wazuh API is protected by Cloudflare Access.' },
      { key: 'accessClientSecret', label: 'Cloudflare Access Client Secret (optional)', placeholder: 'Access service token secret', secret: true, help: 'Stored encrypted; never put this in a public URL.' },
    ],
  },
  {
    id: 'sysmon', name: 'Windows Sysmon', category: 'Endpoint',
    purpose: 'Detailed Windows process, network and registry telemetry.',
    state: 'demo', configured: false, verified: false,
    fields: [
      { key: 'eventChannel', label: 'Sysmon event channel', placeholder: 'Microsoft-Windows-Sysmon/Operational' },
      { key: 'configVersion', label: 'Sysmon config version', placeholder: 'e.g. v14.16 + modular rules' },
    ],
  },
  {
    id: 'clamav', name: 'ClamAV', category: 'Malware',
    purpose: 'Open-source antivirus scanning for files and attachments.',
    state: 'not_configured', configured: false, verified: false,
    fields: [
      { key: 'binaryPath', label: 'ClamAV executable path (optional)', placeholder: 'clamscan or /usr/bin/clamscan' },
    ],
  },
  {
    id: 'yara', name: 'YARA', category: 'Malware',
    purpose: 'Pattern-based malware classification using curated rule sets.',
    state: 'not_configured', configured: false, verified: false,
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
