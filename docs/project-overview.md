# SentinelX — Project Overview

## 1. Introduction

SentinelX is an AI-assisted defensive cybersecurity project designed to support Security Operations Center (SOC) activities through security event processing, detection, investigation, and defensive recommendations.

The project aims to bring multiple defensive capabilities together in a centralized application rather than requiring analysts to work independently across disconnected tools.

## 2. Problem Statement

Security teams receive events from multiple systems, including endpoints, servers, and networks. Investigating these events manually can be time-consuming and may make it difficult to understand the context of a potential attack.

SentinelX aims to help address these challenges by organizing security events, applying detection logic, creating investigation cases, and supporting analysts with contextual explanations and recommended defensive actions.

## 3. Project Objectives

- Collect and validate supported security events.
- Normalize incoming events into a consistent structure.
- Detect suspicious activity using defined detection rules.
- Reduce duplicate alerts and organize events into cases.
- Maintain investigation notes and evidence references.
- Support incident investigation and defensive decision-making.
- Integrate multiple defensive security tools where feasible.
- Provide a graphical user interface for interacting with the system.

## 4. Planned Investigation Workflow

1. Receive a security event from a supported source.
2. Validate the event fields and format.
3. Check whether the event has already been processed.
4. Create a case when the event passes the required checks.
5. Evaluate relevant detection rules.
6. Collect available evidence and investigation context.
7. Generate an analyst-friendly explanation and defensive recommendations.
8. Record investigation results and approved response actions.

The complete workflow will be implemented and verified incrementally.

## 5. Architecture

SentinelX is planned around the following components:

- **Event Ingestion:** Receives and validates security events.
- **Workflow Orchestration:** Coordinates processing and detection workflows.
- **Detection Engine:** Evaluates events against detection rules.
- **Case Management:** Organizes security events and investigation records.
- **Investigation Assistance:** Supports analysis and defensive recommendations.
- **Integrations:** Connects supported defensive security tools.
- **Graphical Interface:** Provides a centralized interface for analysts.

Not every component is fully implemented yet. The architecture will be updated as development progresses.

## 6. Current Implementation

The initial ActivePieces ingestion workflow has been configured with input validation, duplicate checking, case creation, and response handling.

Live webhook authentication has not yet been verified. Additional detection workflows, integrations, investigation assistance, and the graphical interface remain part of the ongoing development work.

## 7. Security and Scope

SentinelX is intended for defensive cybersecurity and authorized environments. Testing must use systems and data that the project owner is authorized to access.

Authentication credentials, private keys, passwords, and sensitive customer information must not be committed to the repository.

## 8. Development Status

**Status:** In Development

This document describes the project's intended architecture and current direction. Planned capabilities should not be interpreted as completed or production-ready features.
## GUI Prototype Update

A React + TypeScript frontend prototype (dark black/red/gold SOC dashboard) has been added at the repository root. It uses **demo data only** and does not claim any live monitoring, AI analysis or integration. See [gui-design.md](gui-design.md).
