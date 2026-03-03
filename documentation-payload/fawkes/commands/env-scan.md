+++
title = "env-scan"
chapter = false
weight = 104
hidden = false
+++

## Summary

Scan process environment variables for leaked credentials, API keys, and secrets. Reads environment blocks from all accessible processes (or a specific PID) and matches variable names against 35+ sensitive patterns covering cloud credentials, database passwords, API keys, CI/CD tokens, and cryptographic secrets.

{{% notice info %}}Linux and macOS Only{{% /notice %}}

### Arguments

#### pid (optional)
Target a specific process by PID. If 0 or omitted, scans all accessible processes.

#### filter (optional)
Filter results by variable name or category (case-insensitive substring match).

## Usage
```
env-scan
env-scan -pid 1234
env-scan -filter aws
env-scan -pid 5678 -filter password
```

### Output Format
Results are grouped by category (e.g., "AWS Credential", "Database URL", "API Key") with redacted values showing first 4 and last 4 characters for values longer than 12 characters.

### Detection Categories
- **Cloud**: AWS credentials, Azure secrets, GCP service accounts
- **Database**: Connection strings, MySQL/PostgreSQL/Redis passwords
- **API**: API keys, access tokens, bearer tokens
- **CI/CD**: GitHub/GitLab/NPM/PyPI tokens
- **Crypto**: JWT secrets, signing keys, private keys, HMAC keys
- **Container**: Docker/registry passwords, Kubernetes config

### Implementation
- **Linux**: Reads `/proc/<pid>/environ` for each accessible process
- **macOS**: Uses `ps eww` to extract environment variables

## MITRE ATT&CK Mapping

- T1057 — Process Discovery
- T1552.001 — Unsecured Credentials: Credentials In Files
