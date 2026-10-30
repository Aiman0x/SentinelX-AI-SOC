# SentinelX — Project Overview

## 1. Introduction

SentinelX is an AI-assisted defensive cybersecurity project designed to support SOC activities through security-event ingestion, detection, correlation, investigation, evidence handling, and defensive recommendations.

The goal is to bring defensive capabilities together in a centralized analyst GUI while retaining human oversight over consequential actions.

## 2. Problem Statement

Security teams receive events from endpoints, servers, and networks. Investigating these events manually can be time-consuming and may make it difficult to understand the context of suspicious activity.

SentinelX aims to validate and correlate security events, organize findings into cases, and help analysts understand what happened and what defensive steps may be appropriate.

## 3. Project Objectives

- Collect and validate authorized security telemetry.
- Normalize events into a consistent structure.
- Detect suspicious activity using defined rules.
- Reduce duplicate alerts and organize findings into cases.
- Maintain investigation notes and evidence references.
- Provide contextual investigation assistance and defensive recommendations.
- Integrate multiple defensive security tools where feasible.
- Provide a secure graphical interface for analysts.

## 4. Current Technology Direction

- **Frontend:** React, TypeScript, Vite, Tailwind.
- **Workflow/backend orchestration:** ActivePieces.
- **API/authentication boundary:** Cloudflare Worker.
- **Encrypted integration configuration storage:** Cloudflare Workers KV with AES-256-GCM encryption.
- **Initial telemetry source:** Local Windows Security Event Log collector, followed by authorized remote telemetry sources.

## 5. Current Implementation

The repository contains a dark SOC GUI prototype and a backend-integration foundation on the `feat/cloudflare-api-gateway` branch. Backend-aware data loaders and mappers are in place for alerts, cases, investigations, evidence, audit logs, assets, detection rules, and integration registry data.

The Cloudflare Worker source includes analyst login, signed sessions, rate limiting, authenticated read routes, and encrypted integration configuration storage. The Worker is not deployed and the GitHub Pages GUI has not yet been configured to use it.

Eight GUI read workflows and selected core telemetry/detection workflows passed structural validation in ActivePieces. This does not establish live connectivity or successful processing of real Windows events.

## 6. Capabilities Still Pending

- Worker deployment and GUI-to-backend session verification.
- Rotated bridge credentials and actual ActivePieces webhook URLs configured securely.
- Tool-specific adapters and connection tests.
- Case, asset, and rule write APIs.
- Verified AI model investigation and recommendations.
- Real-event validation from Windows and authorized remote systems.
- Audited, approval-gated defensive response.

## 7. Security and Scope

SentinelX is intended for defensive cybersecurity in systems the operator is authorized to monitor. Credentials and integration secrets must remain in secure server-side storage. Demo data, structurally valid workflows, and saved tool configurations must not be described as real telemetry, verified connectivity, or working AI.

## 8. Development Status

**Status: In Development — GUI/backend foundation under construction.**

The project will move to real-event and AI verification only after the GUI and backend foundation is configured and connected.
