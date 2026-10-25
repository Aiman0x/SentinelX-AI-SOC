import type { Severity } from './alert';

export type RuleStatus = 'enabled' | 'disabled' | 'draft';
export type RuleMaturity = 'unvalidated' | 'in_testing' | 'validated';

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: Severity;
  source: string;
  mitre: string[];
  status: RuleStatus;
  lastTested?: string;
  maturity: RuleMaturity;
  requiredEvidence: string[];
  logic: string; // descriptive pseudo-logic only; never executed in the browser
  response: string[];
}

export type PlaybookLifecycle = 'designed' | 'configured' | 'executed';

export interface PlaybookStep {
  id: string;
  label: string;
  type: 'trigger' | 'enrich' | 'decision' | 'notify' | 'approval' | 'action';
  disruptive?: boolean;
  branches?: { label: string; to: string }[];
  detail: string;
}

export interface Playbook {
  id: string;
  name: string;
  purpose: string;
  triggers: string[];
  requiredEvidence: string[];
  plannedActions: string[];
  approval: string;
  lifecycle: PlaybookLifecycle;
  lastExecuted?: string;
  steps: PlaybookStep[];
}

export interface AuditRecord {
  id: string;
  time: string;
  actor: string;
  actorType: 'user' | 'service';
  action: string;
  actionType: 'view' | 'create' | 'update' | 'config' | 'response' | 'auth';
  target: string;
  result: 'success' | 'failure' | 'denied';
  source: string;
}
