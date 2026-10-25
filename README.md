# SentinelX — AI-Assisted Security Operations Center

SentinelX is an AI-assisted defensive cybersecurity project designed to support security event ingestion, alert analysis, incident investigation, and response recommendations through a centralized interface.

## Project Objectives

- Ingest and normalize security events.
- Identify suspicious authentication activity using detection rules.
- Organize security alerts into cases for investigation.
- Maintain evidence and incident-related information.
- Provide investigation context and recommended defensive actions.
- Integrate defensive security tools through a modular architecture.

## Core Capabilities

### 1. Security Event Ingestion
A structured ingestion workflow validates incoming security events and checks for duplicate events before creating a case.

### 2. Detection and Triage
Detection workflows are planned to evaluate suspicious activity and support security alert triage.

### 3. Case Management
Security cases can be organized for investigation, evidence tracking, and incident documentation.

### 4. Defensive Integrations
The project is intended to support integrations with defensive security tools as the architecture develops.

### 5. Analyst Assistance
Future development will focus on investigation summaries, explanations of suspicious activity, and defensive recommendations.

## Current Development Status

- [x] Initial project structure defined.
- [x] ActivePieces-based event ingestion workflow configured.
- [x] Input validation and duplicate-checking logic configured.
- [x] Case creation workflow configured.
- [ ] Live webhook authentication testing.
- [ ] Additional detection workflows.
- [ ] Defensive tool integrations.
- [x] Frontend GUI prototype with demo data (React + TypeScript).
- [ ] Investigation and recommendation interface connected to real data and an AI backend.
- [ ] Desktop GUI packaging.

**Note:** Features listed as planned or incomplete are not yet claimed as implemented or production-ready.

## GUI Prototype (React + TypeScript)

SentinelX now includes a dark **black / red / gold** SOC-style frontend prototype. It runs entirely on **sample (demo) data** — no backend, no live telemetry and no external integration is connected.

| Screen | What it does today |
|---|---|
| Overview | KPI cards, events-over-time chart (24h/7d/30d), severity donut, recent alerts, integration health |
| Security Alerts | Search, filters, sortable table, pagination, details drawer, *Create Case* / *Investigate* |
| Incidents & Cases | Case list, filters, create demo case, notes, status + assignee, timeline (saved in browser storage) |
| Investigation | Evidence list, expandable timeline, rule-based *demo* analyst panel (observed / hypothesis / recommended), markdown export |
| Assets & Endpoints | Inventory, filters, *Add Asset* (registers only — never scans); registered vs. verified |
| Integrations | ActivePieces, Wazuh, Sysmon, ClamAV, YARA, Suricata, Zeek — config forms, honest *Test Connection* |
| Detection Rules | Rule table, drawer, editor (logic stored as text, never executed) |
| Response Playbooks | 6 playbook designs, workflow view, typed-confirmation for disruptive steps (simulation only) |
| Audit Logs | Searchable sample audit trail |
| Settings | Preferences, theme, retention, security notes, about |

### Run it

```bash
npm install
npm run dev        # http://localhost:5173
npm run build      # production build -> dist/
npm run preview    # serve the production build
```

Copy `.env.example` to `.env.local` only if you later connect a backend (`VITE_API_BASE_URL`). **Never put secrets in `VITE_*` variables.**

### Honesty rules built into the UI

- A persistent **DEMO MODE** badge shows whenever sample data is used.
- "Connected" is never shown without a real backend health check; *Test Connection* reports "cannot verify" when no backend exists.
- Secret fields (API keys, passwords) are not accepted or stored by the browser.
- Disruptive actions (isolate, disable, block, delete) are simulations and need typed confirmation.
- The AI assistant is a **placeholder**: it clearly separates observed facts, unconfirmed hypotheses and recommendations, and states that no AI model is connected.

See [`docs/gui-design.md`](docs/gui-design.md) for the full design notes and a working / needs-backend feature matrix.

## Technology

- ActivePieces — workflow automation and backend orchestration.
- React, TypeScript, Vite, Tailwind CSS, Recharts, Lucide, React Router — frontend prototype.
- GitHub — source control and project documentation.
- Additional defensive tools and interface technologies will be documented as they are integrated.

## Security Notice

- Never commit API keys, authentication secrets, passwords, or `.env` files.
- Do not upload private customer data or sensitive security logs.
- Test integrations only on systems and data you are authorized to use.
- Live endpoints must be secured and reviewed before use.

## Project Status

**Status:** In Development

SentinelX is an evolving project. Features, integrations, and architecture may change during development.

## License

No license has been selected yet.