# SentinelX Detection Rules

## Purpose
This directory documents the rules used to identify potentially suspicious security events.

## Planned Detection Rules

### 1. Repeated Authentication Failures
Identify multiple failed authentication attempts within a defined period.

### 2. Failed Login Followed by Successful Login
Identify a successful authentication that follows suspicious failed login activity.

### 3. Suspicious Script Interpreter Activity
Identify potentially suspicious use of script interpreters, subject to available telemetry and detection criteria.

### 4. Persistence-Related Changes
Identify selected system changes that may indicate an attempt to maintain unauthorized access.

### 5. Unexpected Remote Logon
Identify remote authentication activity that requires further investigation.

### 6. Regular Outbound Communication
Identify repeated outbound communication patterns that warrant investigation.

### 7. Critical Asset Without Monitoring
Identify important assets that appear to lack expected monitoring coverage.

### 8. Response Requires Approval
Flag proposed response actions that require authorization before execution.

## Rule Documentation Requirements
Each implemented rule should specify:
- Rule identifier and name
- Detection logic
- Required event fields
- Severity
- Relevant MITRE ATT&CK technique, where applicable
- Expected false positives
- Test cases and actual test results
- Current implementation status

## Testing
Rules should be evaluated using synthetic or otherwise authorized security events. A configured rule must not be described as validated until its test results have been verified.

## Current Status
The repository currently documents the planned rule categories. The implementation and runtime effectiveness of each rule must be verified separately.