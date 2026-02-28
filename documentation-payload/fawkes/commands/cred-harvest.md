+++
title = "cred-harvest"
chapter = false
weight = 113
hidden = false
+++

## Summary

Cross-platform credential harvesting across system files, cloud infrastructure, application configurations, and Windows-specific sources. On Unix: extracts password hashes from `/etc/shadow`, discovers cloud provider credentials, and finds application secrets. On Windows: harvests PowerShell history, sensitive environment variables, RDP connections, WiFi profiles, and Windows Vault locations.

{{% notice info %}}Cross-Platform — works on Windows, Linux, and macOS. Actions vary by platform.{{% /notice %}}

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | Yes | `shadow` (Unix): system password hashes. `cloud`: cloud/infrastructure credentials. `configs`: application secrets. `windows` (Windows): PowerShell history, env vars, RDP, WiFi. `all`: run all platform-appropriate actions. |
| user | No | Filter results by username (case-insensitive substring match) |

## Usage

### Linux/macOS
```
# Extract all credentials (shadow + cloud + configs)
cred-harvest -action all

# System password hashes (/etc/shadow, /etc/passwd, /etc/gshadow)
cred-harvest -action shadow

# Cloud provider credentials (AWS, GCP, Azure, K8s, Docker, etc.)
cred-harvest -action cloud

# Application configs and secrets
cred-harvest -action configs

# Filter by specific user
cred-harvest -action shadow -user root
```

### Windows
```
# Extract all credentials (windows + cloud + configs)
cred-harvest -action all

# Windows-specific sources (PowerShell history, env vars, RDP, WiFi)
cred-harvest -action windows

# Cloud provider credentials (same as Unix)
cred-harvest -action cloud

# Application configs and secrets (SSH keys, git creds, .env files)
cred-harvest -action configs

# Filter by user profile
cred-harvest -action all -user admin
```

## Shadow Action (Unix Only)

Extracts from:
- **`/etc/shadow`** — Password hashes (requires root). Skips locked accounts (`*`, `!`, `!!`).
- **`/etc/passwd`** — User accounts with real shells (excludes nologin/false). Warns if legacy password hashes found in passwd.
- **`/etc/gshadow`** — Group password hashes (requires root).

Output includes hashcat/john-compatible hash format (`$6$...`, `$y$...`, etc.).

## Cloud Action (Cross-Platform)

Checks for credentials from 7 cloud/infrastructure platforms:

| Platform | Files Checked | Environment Variables |
|----------|--------------|----------------------|
| AWS | `.aws/credentials`, `.aws/config` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` |
| GCP | `.config/gcloud/credentials.db`, `application_default_credentials.json` | `GOOGLE_APPLICATION_CREDENTIALS` |
| Azure | `.azure/accessTokens.json`, `azureProfile.json`, `msal_token_cache.json` | `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID` |
| Kubernetes | `.kube/config` | `KUBECONFIG` |
| Docker | `.docker/config.json` | `DOCKER_HOST`, `DOCKER_CONFIG` |
| Terraform | `.terraformrc`, `credentials.tfrc.json` | `TF_VAR_access_key`, `TF_VAR_secret_key` |
| Vault | `.vault-token` | `VAULT_TOKEN`, `VAULT_ADDR` |

Small files (<10KB) are read inline. On Unix, scans all user home directories from `/etc/passwd`. On Windows, scans `C:\Users\*` profiles.

## Configs Action (Cross-Platform)

Searches for application secrets and credentials:

| Category | Files Checked |
|----------|--------------|
| Environment Files | `.env`, `.env.local`, `.env.production` |
| Database Configs | `config/database.yml`, `wp-config.php`, `settings.py`, `application.properties`, `appsettings.json` |
| SSH Private Keys | `.ssh/id_rsa`, `.ssh/id_ecdsa`, `.ssh/id_ed25519` |
| Git Credentials | `.git-credentials`, `.gitconfig` |
| Package Tokens | `.npmrc`, `.pypirc`, `.gem/credentials` |
| GNOME Keyring (Unix) | `.local/share/keyrings/*.keyring` |
| System DB Configs (Unix) | `/etc/mysql/debian.cnf`, PostgreSQL `pg_hba.conf`, Redis, MongoDB configs |

For system database configs, extracts lines containing `password`, `secret`, `token`, or `key`.

## Windows Action (Windows Only)

Harvests Windows-specific credential sources:

| Source | What's Harvested |
|--------|-----------------|
| **PowerShell History** | `ConsoleHost_history.txt` — last 50 lines, credential-related commands highlighted (`>>>`) |
| **Sensitive Environment Variables** | Variables containing PASSWORD, SECRET, TOKEN, API_KEY, AUTH, CONNECTION_STRING, etc. |
| **RDP Saved Connections** | `Default.rdp` files — server addresses and usernames |
| **WiFi Profiles** | Profile locations (use `netsh wlan show profiles` to extract keys) |
| **Windows Vault** | Vault directory locations (use `credman` command for detailed enumeration) |

## Credential Vault Integration

Harvested credentials are automatically reported to Mythic's Credentials store:

| Source | Credential Type | What's Reported |
|--------|----------------|-----------------|
| `/etc/shadow` hashes | hash | Username + password hash (e.g., `$6$...`, `$y$...`) |
| Cloud env vars | plaintext | Environment variable name + value (e.g., `AWS_ACCESS_KEY_ID`, `VAULT_TOKEN`) |
| Windows sensitive env vars | plaintext | Environment variable name + value (e.g., `PASSWORD`, `SECRET`, `API_KEY` patterns) |

Credentials are searchable in the Mythic UI under the Credentials tab.

## OPSEC Considerations

- All actions use only file read operations — no subprocess execution, no API calls
- `/etc/shadow` and `/etc/gshadow` require root — non-root gets permission denied
- Cloud credential files are user-readable — no elevation needed
- SSH private keys require same-user or root access
- On Unix, scans all user home directories from `/etc/passwd`
- On Windows, enumerates `C:\Users\*` profiles
- Large credential files (>10KB for cloud, >4KB for configs) show metadata only, not contents
- Environment variable values longer than 40/60 characters are partially masked
- PowerShell history may contain sensitive commands — entire history is returned for review

## MITRE ATT&CK Mapping

- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1003.008** — OS Credential Dumping: /etc/passwd and /etc/shadow
