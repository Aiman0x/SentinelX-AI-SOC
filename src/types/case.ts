import type { Severity } from './alert';

export type CaseStatus = 'open' | 'investigating' | 'contained' | 'resolved' | 'closed';

export interface CaseNote {
  id: string;
  author: string;
  time: string;
  text: string;
}

export interface TimelineEntry {
  id: string;
  time: string;
  title: string;
  detail: string;
  kind: 'detection' | 'analyst' | 'status' | 'evidence' | 'system';
}

export interface SecurityCase {
  id: string;
  title: string;
  severity: Severity;
  status: CaseStatus;
  assignee: string;
  assets: string[];
  createdAt: string;
  updatedAt: string;
  overview: string;
  notes: CaseNote[];
  evidence: string[];
  alertIds: string[];
  timeline: TimelineEntry[];
  recommended: string[];
  /** True when this record comes from the rule-based security_incidents engine. */
  detectionIncident?: boolean;
  /** Provenance for imported/legacy records; these are not automatically live detections. */
  sourceSchema?: string;
  dataOrigin?: string;
  sourceEventId?: string;
  rawEvidence?: string;
  legacyRecord?: boolean;
  analysis?: Record<string, unknown>;
  investigationPlan?: Record<string, unknown>;
}
