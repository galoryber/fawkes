+++
title = "cred-harvest"
chapter = false
weight = 113
hidden = false
+++

## Summary

Cross-platform credential harvesting across system files, cloud infrastructure, application configurations, shell history, Windows-specific sources, Microsoft 365 OAuth tokens, and live browser sessions. On Unix: extracts password hashes from `/etc/shadow`, discovers cloud provider credentials, finds application secrets, and scans shell history for leaked credentials. On Windows: harvests PowerShell history, sensitive environment variables, RDP connections, WiFi profiles, Windows Vault locations, M365 OAuth/JWT tokens, and scans shell history. The `browser-live` action steals live cookies, localStorage, and sessionStorage from running Chrome/Edge instances via the Chrome DevTools Protocol (CDP).

{{% notice info %}}Cross-Platform — works on Windows, Linux, and macOS. Actions vary by platform.{{% /notice %}}

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | Yes | `shadow` (Unix): system password hashes. `cloud`: cloud/infrastructure credentials. `configs`: application secrets. `history`: scan shell history for leaked passwords, tokens, and API keys. `windows` (Windows): PowerShell history, env vars, RDP, WiFi. `m365-tokens` (Windows): OAuth/JWT tokens from TokenBroker, Teams, Outlook. `browser-live`: steal live cookies, localStorage, sessionStorage from Chrome/Edge via CDP. `all`: run all platform-appropriate actions. `dump-all` (Windows): automated subtask chain — runs hashdump + lsa-secrets + cred-harvest all in parallel. |
| user | No | Filter results by username (case-insensitive substring match) |

## Usage

### Linux/macOS
```
# Extract all credentials (shadow + cloud + configs + history)
cred-harvest -action all

# System password hashes (/etc/shadow, /etc/passwd, /etc/gshadow)
cred-harvest -action shadow

# Cloud provider credentials (AWS, GCP, Azure, K8s, Docker, etc.)
cred-harvest -action cloud

# Application configs and secrets
cred-harvest -action configs

# Scan shell history for leaked credentials
cred-harvest -action history

# Filter by specific user
cred-harvest -action shadow -user root
```

### Windows
```
# Extract all credentials (windows + cloud + configs + m365-tokens + history)
cred-harvest -action all

# Windows-specific sources (PowerShell history, env vars, RDP, WiFi)
cred-harvest -action windows

# Microsoft 365 OAuth/JWT tokens (TokenBroker, Teams, Outlook)
cred-harvest -action m365-tokens

# Cloud provider credentials (same as Unix)
cred-harvest -action cloud

# Application configs and secrets (SSH keys, git creds, .env files)
cred-harvest -action configs

# Scan shell/PowerShell history for leaked credentials
cred-harvest -action history

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

## History Action (Cross-Platform)

Scans shell history files for leaked credentials — passwords, tokens, and API keys accidentally typed into commands. Supports multiple shell formats and application-specific histories.

| Shell/App | History Files Checked |
|-----------|---------------------|
| Bash | `~/.bash_history` |
| Zsh | `~/.zsh_history`, `~/.zhistory` (extended format supported) |
| Fish | `~/.local/share/fish/fish_history` (YAML format parsed) |
| MySQL | `~/.mysql_history` |
| PostgreSQL | `~/.psql_history` |
| Redis CLI | `~/.rediscli_history` |
| Python | `~/.python_history` |
| Node.js | `~/.node_repl_history` |
| PowerShell (Windows) | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` |

**Credential patterns detected:**

| Pattern | Example | Category |
|---------|---------|----------|
| `sshpass -p` | `sshpass -p 'secret' ssh user@host` | SSH Password |
| `mysql -p<pass>` | `mysql -u root -pSECRET mydb` | MySQL Password |
| `curl -u user:pass` | `curl -u admin:pass123 https://api.example.com` | HTTP Credential |
| `curl -H Authorization` | `curl -H "Authorization: Bearer eyJ..."` | HTTP Credential |
| `wget --password=` | `wget --password=secret ftp://server/file` | HTTP Credential |
| `docker login -p` | `docker login -p token registry.io` | Docker Registry Password |
| `htpasswd -b` | `htpasswd -b .htpasswd admin pass` | htpasswd Password |
| `psql postgres://` | `psql postgres://user:pass@host/db` | PostgreSQL Credential |
| `export SECRET_KEY=` | `export AWS_SECRET_ACCESS_KEY=wJalr...` | Exported Secret |
| `git clone https://token@` | `git clone https://ghp_abc@github.com/...` | Git Token |
| `echo pass \| sudo -S` | `echo 'pass' \| sudo -S cmd` | Sudo Password |

Findings are deduplicated and grouped by category. Values are partially redacted in output (first 4 + last 4 characters for values >12 chars).

## Windows Action (Windows Only)

Harvests Windows-specific credential sources:

| Source | What's Harvested |
|--------|-----------------|
| **PowerShell History** | `ConsoleHost_history.txt` — last 50 lines, credential-related commands highlighted (`>>>`) |
| **Sensitive Environment Variables** | Variables containing PASSWORD, SECRET, TOKEN, API_KEY, AUTH, CONNECTION_STRING, etc. |
| **RDP Saved Connections** | `Default.rdp` files — server addresses and usernames |
| **WiFi Profiles** | Profile locations (use `netsh wlan show profiles` to extract keys) |
| **Windows Vault** | Vault directory locations (use `credman` command for detailed enumeration) |

## M365 Tokens Action (Windows Only)

Extracts OAuth/JWT tokens from three Microsoft 365 sources:

| Source | Location | Encryption | What's Extracted |
|--------|----------|------------|------------------|
| **TokenBroker Cache** | `%LOCALAPPDATA%\Microsoft\TokenBroker\Cache\*.tbres` | DPAPI | Access tokens, refresh tokens, resource URLs, client IDs |
| **Teams EBWebView** | `%LOCALAPPDATA%\Packages\MSTeams_*\...\EBWebView\` | AES-256-GCM (DPAPI key) | Auth cookies: ESTSAUTH, authtoken, skypetoken_asm, etc. |
| **Outlook (New) EBWebView** | `%LOCALAPPDATA%\Microsoft\Olk\EBWebView\` | AES-256-GCM (DPAPI key) | Auth cookies: ESTSAUTH, OIDCAuthCookie, FedAuth, etc. |
| **OneAuth Metadata** | `%LOCALAPPDATA%\Microsoft\OneAuth\accounts\` | Plaintext | Account UPN, tenant ID, display name |

Recognizes 17 specific M365 auth cookie patterns plus generic token name detection. TokenBroker files are UTF-16LE JSON with DPAPI-protected response bytes containing structured token data.

EBWebView cookie decryption uses the same Chromium pattern as the `browser` command: reads `Local State` → DPAPI decrypts the AES key → AES-256-GCM decrypts cookie values.

## Browser-Live Action (Cross-Platform — CDP)

Connects to running Chrome/Edge instances via the **Chrome DevTools Protocol (CDP)** to extract live session data. Unlike the static `browser` command (which reads SQLite databases), `browser-live` captures data from the running browser process — including **HttpOnly cookies** that are inaccessible to JavaScript and client-side tools.

### How It Works

1. **Discovery**: Checks for `DevToolsActivePort` files in browser user data directories (Chrome, Edge, Chromium). Falls back to probing common debug ports (9222-9229).
2. **Connection**: Opens a WebSocket connection to the browser's CDP endpoint.
3. **Cookie Extraction**: Sends `Network.getAllCookies` — retrieves ALL cookies from ALL domains, including HttpOnly/Secure cookies.
4. **Storage Extraction**: Evaluates JavaScript via `Runtime.evaluate` in each open tab to read `localStorage` and `sessionStorage`.
5. **Filtering**: Auth-related items (cookies/keys containing "session", "token", "auth", "jwt", "csrf", "oauth", etc.) are highlighted and registered as credentials.

### Requirements

The target browser must have been started with `--remote-debugging-port` for CDP to be accessible. Chrome writes the assigned port to a `DevToolsActivePort` file in its user data directory.

### Usage
```
# Steal live browser sessions
cred-harvest -action browser-live
```

### Output

Reports total cookies, auth-related cookies with domain/name/value/flags, localStorage/sessionStorage entries with auth-related keys, and a list of open tabs. Auth cookies and storage entries are automatically registered in the Mythic Credential Vault.

## Credential Vault Integration

Harvested credentials are automatically reported to Mythic's Credentials store:

| Source | Credential Type | What's Reported |
|--------|----------------|-----------------|
| `/etc/shadow` hashes | hash | Username + password hash (e.g., `$6$...`, `$y$...`) |
| Cloud env vars | plaintext | Environment variable name + value (e.g., `AWS_ACCESS_KEY_ID`, `VAULT_TOKEN`) |
| Windows sensitive env vars | plaintext | Environment variable name + value (e.g., `PASSWORD`, `SECRET`, `API_KEY` patterns) |
| TokenBroker tokens | token | Client ID + access/refresh token, resource URL |
| EBWebView auth cookies | token | Cookie name + decrypted value, host domain |
| CDP live cookies | plaintext | Auth cookie name + value, domain |
| CDP localStorage | plaintext | Auth-related key + value, origin |
| CDP sessionStorage | plaintext | Auth-related key + value, origin |

Credentials are searchable in the Mythic UI under the Credentials tab.

## Dump-All Action (Windows — Subtask Chain)

The `dump-all` action creates a **Mythic subtask chain** that runs three credential extraction commands simultaneously:

| Subtask | What It Does | Requirements |
|---------|-------------|--------------|
| `hashdump` | Dump SAM database (local NTLM hashes) | SYSTEM privileges |
| `lsa-secrets` -action dump | Dump LSA secrets (DPAPI keys, cached domain creds, auto-logon) | SYSTEM privileges |
| `cred-harvest` -action all | Harvest all file-based credentials (shadow, cloud, configs, history, windows, m365-tokens) | User-level |

All three subtasks execute in parallel. When all complete, a group completion function aggregates results and summarizes findings in the parent task output. Credentials from all sources are registered in Mythic's Credential Vault.

```
# Run full credential harvest chain (requires SYSTEM/admin)
cred-harvest -action dump-all
```

{{% notice warning %}}The dump-all chain accesses SAM, LSA, and LSASS memory simultaneously. This creates a high detection footprint — multiple credential access techniques (T1003.002, T1003.004, T1003.005) in rapid succession. Use only when stealth is not a priority.{{% /notice %}}

## OPSEC Considerations

- Most actions use only file read operations — no subprocess execution, no API calls
- M365 tokens action calls `CryptUnprotectData` (DPAPI) — standard Windows API, same user context
- `/etc/shadow` and `/etc/gshadow` require root — non-root gets permission denied
- Cloud credential files are user-readable — no elevation needed
- SSH private keys require same-user or root access
- On Unix, scans all user home directories from `/etc/passwd`
- On Windows, enumerates `C:\Users\*` profiles
- Large credential files (>10KB for cloud, >4KB for configs) show metadata only, not contents
- Environment variable values longer than 40/60 characters are partially masked
- PowerShell history may contain sensitive commands — entire history is returned for review
- History action reads history files from disk — file read only, no subprocess execution
- Shell history credential values are partially redacted in output (first 4 + last 4 characters)
- History findings are deduplicated to reduce output volume
- `browser-live` reads `DevToolsActivePort` files and connects to localhost debug ports — EDR may flag debug port probing
- CDP WebSocket connections use unencrypted `ws://` on localhost — no network-level exposure
- `Network.getAllCookies` extracts ALL cookies including HttpOnly — more comprehensive than JavaScript-based theft

## MITRE ATT&CK Mapping

- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.003** — Unsecured Credentials: Bash History
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1003.008** — OS Credential Dumping: /etc/passwd and /etc/shadow
- **T1528** — Steal Application Access Token
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
