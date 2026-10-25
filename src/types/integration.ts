export type IntegrationState = 'connected' | 'disconnected' | 'error' | 'not_configured' | 'demo';

export interface IntegrationField {
  key: string;
  label: string;
  placeholder: string;
  /** Secret fields are NEVER stored in the browser. A backend / secrets store is required. */
  secret?: boolean;
  help?: string;
}

export interface Integration {
  id: string;
  name: string;
  purpose: string;
  category: 'Orchestration' | 'Endpoint' | 'Malware' | 'Network' | 'SIEM';
  /** Sample state for the demo UI. Never "connected" unless a real health check passed. */
  state: IntegrationState;
  /** Non-secret configuration has been saved (not the same as verified). */
  configured: boolean;
  /** A real health check has succeeded. Always false in the frontend-only prototype. */
  verified: boolean;
  lastHealthCheck?: string;
  fields: IntegrationField[];
}

export interface TestResult {
  ok: boolean;
  /** true when the test could not be performed at all (e.g. no backend). */
  unavailable?: boolean;
  message: string;
  at: string;
}
