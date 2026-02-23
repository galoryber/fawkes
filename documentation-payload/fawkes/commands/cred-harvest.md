+++
title = "cred-harvest"
chapter = false
weight = 113
hidden = false
+++

## Summary

Credential harvesting across system files, cloud infrastructure, and application configurations. Extracts password hashes from `/etc/shadow`, discovers cloud provider credentials (AWS, GCP, Azure, Kubernetes, Docker, Terraform, Vault), and finds application secrets (database configs, API tokens, SSH keys, GNOME keyring).

{{% notice info %}}Linux/macOS Only{{% /notice %}}

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | Yes | `shadow`: system password hashes + account info. `cloud`: cloud/infrastructure credentials. `configs`: application secrets. `all`: run all three. |
| user | No | Filter results by username (case-insensitive substring match) |

## Usage

```
# Extract all credentials
cred-harvest -action all

# System password hashes (/etc/shadow, /etc/passwd, /etc/gshadow)
cred-harvest -action shadow

# Cloud provider credentials (AWS, GCP, Azure, K8s, Docker, etc.)
cred-harvest -action cloud

# Application configs and secrets
cred-harvest -action configs

# Filter by specific user
cred-harvest -action shadow -user root
cred-harvest -action all -user admin
```

## Shadow Action

Extracts from:
- **`/etc/shadow`** — Password hashes (requires root). Skips locked accounts (`*`, `!`, `!!`).
- **`/etc/passwd`** — User accounts with real shells (excludes nologin/false). Warns if legacy password hashes found in passwd.
- **`/etc/gshadow`** — Group password hashes (requires root).

Output includes hashcat/john-compatible hash format (`$6$...`, `$y$...`, etc.).

## Cloud Action

Checks for credentials from 7 cloud/infrastructure platforms:

| Platform | Files Checked | Environment Variables |
|----------|--------------|----------------------|
| AWS | `~/.aws/credentials`, `~/.aws/config` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` |
| GCP | `~/.config/gcloud/credentials.db`, `application_default_credentials.json` | `GOOGLE_APPLICATION_CREDENTIALS` |
| Azure | `~/.azure/accessTokens.json`, `azureProfile.json`, `msal_token_cache.json` | `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID` |
| Kubernetes | `~/.kube/config` | `KUBECONFIG` |
| Docker | `~/.docker/config.json` | `DOCKER_HOST`, `DOCKER_CONFIG` |
| Terraform | `~/.terraformrc`, `credentials.tfrc.json` | `TF_VAR_access_key`, `TF_VAR_secret_key` |
| Vault | `~/.vault-token` | `VAULT_TOKEN`, `VAULT_ADDR` |

Small files (<10KB) are read inline. Scans all user home directories from `/etc/passwd`.

## Configs Action

Searches for application secrets and credentials:

| Category | Files Checked |
|----------|--------------|
| Environment Files | `.env`, `.env.local`, `.env.production` |
| Database Configs | `config/database.yml`, `wp-config.php`, `settings.py`, `application.properties`, `appsettings.json` |
| SSH Private Keys | `.ssh/id_rsa`, `.ssh/id_ecdsa`, `.ssh/id_ed25519` |
| Git Credentials | `.git-credentials`, `.gitconfig` |
| Package Tokens | `.npmrc`, `.pypirc`, `.gem/credentials` |
| GNOME Keyring | `.local/share/keyrings/*.keyring` |
| System DB Configs | `/etc/mysql/debian.cnf`, PostgreSQL `pg_hba.conf`, Redis, MongoDB configs |

For system database configs, extracts lines containing `password`, `secret`, `token`, or `key`.

## OPSEC Considerations

- All actions use only file read operations — no subprocess execution
- `/etc/shadow` and `/etc/gshadow` require root — non-root gets permission denied
- Cloud credential files are user-readable — no elevation needed
- SSH private keys require same-user or root access
- Scans all user home directories from `/etc/passwd` — enumeration may be logged
- Large credential files (>10KB for cloud, >4KB for configs) show metadata only, not contents
- Environment variable values longer than 40 characters are partially masked

## MITRE ATT&CK Mapping

- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1003.008** — OS Credential Dumping: /etc/passwd and /etc/shadow
