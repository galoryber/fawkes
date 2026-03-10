+++
title = "browser"
chapter = false
weight = 25
hidden = false
+++

## Summary

Harvest browser data from Chromium-based browsers (Chrome, Edge, Chromium). Cross-platform support for browsing history, autofill form data, and bookmarks. Windows additionally supports credential and cookie extraction via DPAPI + AES-GCM decryption. Automatically handles multiple browser profiles.

### Platform Support

| Action | Windows | macOS | Linux |
|--------|---------|-------|-------|
| passwords | Yes (DPAPI) | No | No |
| cookies | Yes (DPAPI) | No | No |
| history | Yes | Yes | Yes |
| autofill | Yes | Yes | Yes |
| bookmarks | Yes | Yes | Yes |

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| action | choose_one | No | history | `passwords` — saved login credentials (Windows only); `cookies` — session cookies (Windows only); `history` — browsing history; `autofill` — form data; `bookmarks` — saved URLs |
| browser | choose_one | No | all | `all`, `chrome`, `edge`, or `chromium` — which browser(s) to target |

## Usage

### Harvest Browsing History

Extract recent browsing history (last 500 entries per profile):
```
browser -action history
```

### Target Specific Browser

Harvest from Chrome only:
```
browser -action history -browser chrome
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

### Harvest Credentials (Windows Only)

Extract saved passwords from all installed Chromium-based browsers:
```
browser -action passwords
```

### Harvest Cookies (Windows Only)

Extract session cookies from all browsers:
```
browser -action cookies
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

## How It Works

### All Platforms (history, autofill, bookmarks)

1. Locates browser data directories based on OS (e.g., `~/.config/google-chrome` on Linux, `~/Library/Application Support/Google/Chrome` on macOS, `%LOCALAPPDATA%\Google\Chrome\User Data` on Windows)
2. Discovers profiles (Default, Profile 1, Profile 2, etc.)
3. Copies SQLite databases to temp files to avoid browser lock contention
4. Queries the relevant table (urls, autofill, or Bookmarks JSON file)
5. Cleans up temp files after extraction

### Windows Only (passwords, cookies)

1. Additionally reads `Local State` JSON to extract the base64-encoded encryption key
2. Strips the "DPAPI" prefix and decrypts the AES key using `CryptUnprotectData`
3. For encrypted data: decrypts using AES-256-GCM with the recovered key

## Notes

- **Cross-platform:** History, autofill, and bookmarks work on Windows, macOS, and Linux
- **Windows-only:** Passwords and cookies require DPAPI (user-bound key decryption)
- The browser does not need to be closed — databases are copied to avoid lock conflicts
- Multi-profile support: automatically discovers Default and numbered profiles
- Supported browsers: Chrome, Edge, Chromium (all three on all platforms)
- History/autofill returns up to 500 most recent entries per profile
- Chrome timestamps use a custom epoch (microseconds since 1601-01-01 UTC); auto-detected
- Bookmarks are stored as a JSON file (no database, no encryption)

## MITRE ATT&CK Mapping

- T1555.003 — Credentials from Password Stores: Credentials from Web Browsers
- T1217 — Browser Information Discovery
