+++
title = "browser"
chapter = false
weight = 25
hidden = false
+++

{{% notice info %}}Windows Only{{% /notice %}}

## Summary

Harvest saved credentials from Chromium-based browsers (Chrome, Edge) using DPAPI + AES-GCM decryption. Reads the browser's `Local State` file to extract the AES encryption key (protected by Windows DPAPI), then queries the `Login Data` SQLite database for saved passwords and decrypts them. Supports both modern AES-256-GCM encryption (v10/v11 prefix) and legacy DPAPI-only format. Automatically handles multiple browser profiles.

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| action | choose_one | No | passwords | `passwords` — harvest saved login credentials |
| browser | choose_one | No | all | `all`, `chrome`, or `edge` — which browser(s) to target |

## Usage

### Harvest All Browser Credentials

Extract saved passwords from all installed Chromium-based browsers:
```
browser
```

### Target Specific Browser

Harvest from Chrome only:
```
browser -action passwords -browser chrome
```

Harvest from Edge only:
```
browser -action passwords -browser edge
```

### Example Output (credentials found)
```
=== Browser Credentials (3 found) ===

Browser:  Edge
URL:      https://login.example.com/
Username: user@example.com
Password: P@ssw0rd123

Browser:  Edge (Profile 2)
URL:      https://portal.corp.local/
Username: admin
Password: SecretPass!

Browser:  Chrome
URL:      https://github.com/login
Username: devuser
Password: gh_token_abc123
```

### Example Output (no credentials)
```
=== Browser Credentials (0 found) ===

No Chromium-based browsers found or no saved credentials.
```

## How It Works

1. Locates browser `User Data` directory in `%LOCALAPPDATA%`
2. Reads `Local State` JSON to extract the base64-encoded encryption key
3. Strips the "DPAPI" prefix and decrypts the AES key using `CryptUnprotectData`
4. Copies `Login Data` SQLite database to a temp file (avoids browser lock)
5. Queries the `logins` table for saved credentials
6. Decrypts each password using AES-256-GCM with the recovered key
7. Cleans up temp files after extraction

## Notes

- The agent must run as the same user who saved the credentials (DPAPI is user-bound)
- The browser does not need to be closed — Login Data is copied to avoid lock conflicts
- Multi-profile support: automatically discovers Default and numbered profiles (Profile 1, Profile 2, etc.)
- Legacy passwords (pre-v80 Chrome) use direct DPAPI encryption and are also supported

## MITRE ATT&CK Mapping

- T1555.003 — Credentials from Password Stores: Credentials from Web Browsers
