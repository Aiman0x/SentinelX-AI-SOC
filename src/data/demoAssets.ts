import type { Asset } from '../types/asset';
import { minutesAgo } from '../utils/formatDate';

/** DEMO DATA — fictional assets. "verified" here is sample state, not a real telemetry check. */
export const demoAssets: Asset[] = [
  { id: 'AST-001', name: 'Finance Workstation 14', host: 'WS-FIN-014', ip: '10.20.4.14', os: 'Windows 11', type: 'Workstation', criticality: 'high', monitoring: 'verified', method: 'Sysmon + Wazuh agent', lastEvent: minutesAgo(3), addedBy: 'demo' },
  { id: 'AST-002', name: 'Primary Domain Controller', host: 'SRV-DC-01', ip: '10.20.0.10', os: 'Windows Server 2022', type: 'Server', criticality: 'critical', monitoring: 'verified', method: 'Wazuh agent', lastEvent: minutesAgo(1), addedBy: 'demo' },
  { id: 'AST-003', name: 'Public Web Server 2', host: 'SRV-WEB-02', ip: '10.20.2.12', os: 'Ubuntu 22.04', type: 'Server', criticality: 'high', monitoring: 'verified', method: 'Wazuh agent', lastEvent: minutesAgo(6), addedBy: 'demo' },
  { id: 'AST-004', name: 'File Server', host: 'SRV-FILE-01', ip: '10.20.1.20', os: 'Windows Server 2019', type: 'Server', criticality: 'high', monitoring: 'stale', method: 'Wazuh agent', lastEvent: minutesAgo(3100), addedBy: 'demo' },
  { id: 'AST-005', name: 'HR Workstation 07', host: 'WS-HR-007', ip: '10.20.7.7', os: 'Windows 11', type: 'Workstation', criticality: 'medium', monitoring: 'verified', method: 'Sysmon', lastEvent: minutesAgo(12), addedBy: 'demo' },
  { id: 'AST-006', name: 'Marketing Workstation 03', host: 'WS-MKT-003', ip: '10.20.6.3', os: 'Windows 10', type: 'Workstation', criticality: 'medium', monitoring: 'verified', method: 'Endpoint AV', lastEvent: minutesAgo(25), addedBy: 'demo' },
  { id: 'AST-007', name: 'Dev Workstation 21', host: 'WS-DEV-021', ip: '10.20.5.21', os: 'Ubuntu 24.04', type: 'Workstation', criticality: 'low', monitoring: 'registered', method: 'Wazuh agent (pending)', addedBy: 'demo' },
  { id: 'AST-008', name: 'VPN Gateway', host: 'VPN-GW-01', ip: '10.20.0.2', os: 'FortiOS', type: 'Network device', criticality: 'high', monitoring: 'verified', method: 'Syslog', lastEvent: minutesAgo(2), addedBy: 'demo' },
  { id: 'AST-009', name: 'Finance Database', host: 'DB-FIN-01', ip: '10.20.9.5', os: 'Windows Server 2022', type: 'Database', criticality: 'critical', monitoring: 'unmonitored', method: 'None', addedBy: 'demo' },
  { id: 'AST-010', name: 'Corporate Domain', host: 'corp.example.com', ip: '—', os: '—', type: 'Domain', criticality: 'medium', monitoring: 'registered', method: 'None (registered only)', addedBy: 'demo' },
  { id: 'AST-011', name: 'Cloud Storage Tenant', host: 'storage.example.net', ip: '—', os: '—', type: 'Cloud service', criticality: 'medium', monitoring: 'unmonitored', method: 'None', addedBy: 'demo' },
  { id: 'AST-012', name: 'Core Switch', host: 'SW-CORE-01', ip: '10.20.0.1', os: 'Cisco IOS', type: 'Network device', criticality: 'high', monitoring: 'registered', method: 'Syslog (pending)', addedBy: 'demo' },
];
