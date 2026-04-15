+++
title = "cloud-metadata"
chapter = false
weight = 203
hidden = false
+++

## Summary

Probe cloud instance metadata services to extract IAM credentials, instance identity, user-data scripts, and network configuration. Automatically detects the cloud provider (AWS, Azure, GCP, DigitalOcean) or can target a specific one. Supports AWS IMDSv2 token-based authentication.

This is a critical reconnaissance command for cloud environments — instance metadata services often expose temporary IAM credentials, service account tokens, and user-data scripts that may contain secrets.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | detect | Action: `detect`, `all`, `creds`, `identity`, `userdata`, `network`, `aws-iam`, `azure-graph`, `gcp-iam`, `aws-persist`, `azure-persist` |
| provider | No | auto | Cloud provider: `auto`, `aws`, `azure`, `gcp`, `digitalocean` |
| timeout | No | 3 | Per-request timeout in seconds |

### Actions

- **detect** — Probe all metadata endpoints and report which cloud provider is detected
- **all** — Dump all available metadata from detected/specified provider
- **creds** / **iam** — Extract IAM credentials (AWS role creds, Azure managed identity tokens, GCP service account tokens)
- **identity** — Instance identity information (instance ID, region, account, VM name)
- **userdata** — User-data/startup scripts (may contain passwords, API keys, config secrets)
- **network** — Network configuration (IPs, VPCs, subnets, MACs, security groups)
- **aws-iam** — AWS IAM privilege enumeration: STS caller identity, attached/inline role policies
- **azure-graph** — Azure AD enumeration via Microsoft Graph: users, groups, app registrations
- **gcp-iam** — GCP IAM enumeration: project IAM bindings, service accounts, assigned scopes
- **aws-persist** — AWS IAM persistence: create long-lived IAM access key via CreateAccessKey API (T1098.001)
- **azure-persist** — Azure AD persistence: create app registration with client secret via Microsoft Graph (T1098.001)

## Usage

Auto-detect cloud environment:
```
cloud-metadata
cloud-metadata -action detect
```

Extract IAM credentials:
```
cloud-metadata -action creds
```

Dump all metadata from AWS specifically:
```
cloud-metadata -action all -provider aws
```

Get user-data scripts (check for secrets):
```
cloud-metadata -action userdata
```

Enumerate AWS IAM privileges (uses IMDS credentials):
```
cloud-metadata -action aws-iam
```

Enumerate Azure AD via Microsoft Graph (uses managed identity):
```
cloud-metadata -action azure-graph
```

Enumerate GCP IAM bindings and service accounts:
```
cloud-metadata -action gcp-iam
```

## Supported Providers

| Provider | Endpoint | Auth Header |
|----------|----------|-------------|
| AWS EC2 | `http://169.254.169.254/latest/` | IMDSv2 token (auto-acquired via PUT) |
| Azure | `http://169.254.169.254/metadata/` | `Metadata: true` |
| GCP | `http://metadata.google.internal/` | `Metadata-Flavor: Google` |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` | None |

## MITRE ATT&CK Mapping

- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1580** — Cloud Infrastructure Discovery
