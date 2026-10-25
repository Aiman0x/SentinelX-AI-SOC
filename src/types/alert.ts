export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type AlertStatus = 'open' | 'investigating' | 'resolved' | 'false_positive';

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
}

export interface Alert {
  id: string;
  eventId: string;
  ruleName: string;
  severity: Severity;
  source: string; // e.g. "Windows Security", "Sysmon"
  asset: string;
  sourceIp: string;
  timestamp: string; // ISO
  status: AlertStatus;
  summary: string;
  rawEvent: Record<string, string | number | boolean>;
  evidence: string[];
  relatedAlertIds: string[];
  mitre: MitreTechnique[];
  nextSteps: string[];
  caseId?: string;
}
