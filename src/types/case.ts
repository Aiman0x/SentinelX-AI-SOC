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
}
