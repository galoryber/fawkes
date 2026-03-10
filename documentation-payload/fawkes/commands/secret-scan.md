+++
title = "secret-scan"
chapter = false
weight = 175
hidden = false
+++

## Summary

Search files on the target system for secrets, API keys, private keys, connection strings, and other sensitive patterns. Uses 20+ compiled regex patterns to detect common credential formats.

Complements `env-scan` (environment variables) and `cred-harvest` (OS credential stores) by scanning **file contents** for embedded secrets that aren't stored in standard credential locations.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| path | No | User home dir | Root directory to begin scanning |
| depth | No | 5 | Maximum directory recursion depth |
| max_results | No | 100 | Maximum findings to return |

## Detected Patterns

- **Cloud:** AWS access keys, AWS secret keys, Azure credentials, GCP service account keys
- **VCS/CI:** GitHub tokens (classic + fine-grained), GitLab tokens
- **Messaging:** Slack tokens, Slack webhooks
- **Payment:** Stripe API keys
- **Email:** SendGrid, Twilio
- **Generic:** API keys, secrets, tokens, passwords, connection strings (JDBC, MongoDB, PostgreSQL, Redis, etc.)
- **Crypto:** Private keys (RSA, EC, DSA, OpenSSH)
- **Package:** NPM tokens, Heroku API keys

## File Types Scanned

Config files (`.env`, `.yml`, `.json`, `.xml`, `.toml`, `.ini`, `.conf`), scripts (`.sh`, `.py`, `.ps1`, `.rb`, `.js`), infrastructure (`.tf`, `.tfvars`, `.hcl`), and sensitive dotfiles (`.netrc`, `.pgpass`, `.npmrc`, `.pypirc`).

## OPSEC Notes

- File reads only (no writes, no process spawns)
- Skips `node_modules`, `.git`, `vendor`, `__pycache__`, `.cache` directories
- Skips files > 10MB
- Secret values are **redacted** in output for operator safety

## Usage

```
# Scan home directory with defaults
secret-scan

# Scan specific path with limited depth
secret-scan -path /opt/apps -depth 3

# Get more results
secret-scan -max_results 500
```

## MITRE ATT&CK Mapping

- T1552.001 — Unsecured Credentials: Credentials In Files
- T1005 — Data from Local System
