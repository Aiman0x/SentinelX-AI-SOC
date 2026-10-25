# SentinelX Backend

## Purpose
This directory is intended for backend application logic and coordination between the SentinelX graphical interface and its security workflows.

## Planned Responsibilities
- Process normalized security events.
- Coordinate event analysis and case management.
- Connect the application interface to approved backend services.
- Handle errors and integration status.
- Support secure communication with configured services.

## Current Backend
ActivePieces is currently being used to develop and orchestrate SentinelX workflows.

The existing ActivePieces workflows remain hosted in ActivePieces. They are not automatically stored in this GitHub repository.

## Security Requirements
- Never hardcode credentials or API keys.
- Keep authentication secrets out of source control.
- Validate incoming data.
- Log useful diagnostic information without exposing sensitive values.

## Current Status
Under development. A standalone backend implementation and GUI connection have not yet been completed.