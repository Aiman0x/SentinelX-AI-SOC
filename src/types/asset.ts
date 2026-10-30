export type AssetType = 'Server' | 'Workstation' | 'Domain' | 'Network device' | 'Cloud service' | 'Database';
export type Criticality = 'critical' | 'high' | 'medium' | 'low';

/**
 * registered   – exists in the SentinelX inventory only. No telemetry has been verified.
 * verified     – telemetry was received through a configured, authorised integration.
 * stale        – telemetry was verified before, but nothing has arrived recently.
 * unmonitored  – known asset with no monitoring method.
 */
export type MonitoringState = 'registered' | 'verified' | 'stale' | 'unmonitored';

export interface Asset {
  id: string;
  name: string;
  host: string;
  ip: string;
  os: string;
  type: AssetType;
  criticality: Criticality;
  monitoring: MonitoringState;
  method: string; // e.g. "Wazuh agent", "Sysmon", "None"
  lastEvent?: string; // ISO
  lastVerified?: string; // ISO
  addedBy?: 'demo' | 'user';
}
