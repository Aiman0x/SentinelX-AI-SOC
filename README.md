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
- [ ] Investigation and recommendation interface.
- [ ] Desktop GUI packaging.

**Note:** Features listed as planned or incomplete are not yet claimed as implemented or production-ready.

## Technology

- ActivePieces — workflow automation and backend orchestration.
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