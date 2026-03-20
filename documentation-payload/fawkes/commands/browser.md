+++
title = "browser"
chapter = false
weight = 25
hidden = false
+++

## Summary

Harvest browser data from Chromium-based browsers (Chrome, Edge, Chromium) and Firefox. Cross-platform support for browsing history, autofill form data, and bookmarks. Windows additionally supports Chromium credential and cookie extraction via DPAPI + AES-GCM decryption. Firefox cookies are plaintext and available on all platforms.

### Platform Support

| Action | Windows (Chromium) | Windows (Firefox) | macOS/Linux (Chromium) | macOS/Linux (Firefox) |
|--------|-------------------|-------------------|----------------------|---------------------|
| passwords | Yes (DPAPI) | No | No | No |
| cookies | Yes (DPAPI) | Yes (plaintext) | No | Yes (plaintext) |
| history | Yes | Yes | Yes | Yes |
| autofill | Yes | Yes | Yes | Yes |
| bookmarks | Yes | Yes | Yes | Yes |

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| action | choose_one | No | history | `passwords` — saved login credentials (Windows Chromium only); `cookies` — session cookies (Windows Chromium DPAPI; Firefox plaintext on all platforms); `history` — browsing history; `autofill` — form data; `bookmarks` — saved URLs |
| browser | choose_one | No | all | `all`, `chrome`, `edge`, `chromium`, or `firefox` — which browser(s) to target |

## Usage

### Harvest Browsing History

Extract recent browsing history (last 500 entries per profile):
```
browser -action history
```

### Target Specific Browser

Harvest from Firefox only:
```
browser -action history -browser firefox
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

### Harvest Credentials (Windows Chromium Only)

Extract saved passwords from all installed Chromium-based browsers:
```
browser -action passwords
```

### Harvest Cookies

Extract Firefox cookies (all platforms):
```
browser -action cookies -browser firefox
```

Extract Chromium cookies (Windows only — DPAPI):
```
browser -action cookies -browser chrome
```

### Example Output (history)
```
=== Browser History (5 entries) ===

[Chrome] Company Intranet Portal
  https://intranet.corp.local/dashboard  (visits: 47, last: 2026-03-05 14:30:22)
[Chrome] AWS Console
  https://console.aws.amazon.com/  (visits: 12, last: 2026-03-05 10:15:00)
[Firefox (abc123.default-release)] GitHub
  https://github.com/  (visits: 25, last: 2026-03-05 13:00:00)
[Edge] SharePoint
  https://company.sharepoint.com/  (visits: 8, last: 2026-03-04 09:00:00)
```

### Example Output (Firefox cookies)
```
=== Firefox Cookies (2 entries) ===

[Firefox (abc123.default-release)] .github.com: _gh_sess = abc1...xyz9  (path: /, expires: 2026-04-01 00:00:00) [Secure] [HttpOnly]
[Firefox (abc123.default-release)] login.microsoftonline.com: ESTSAUTH = eyJ0...  (path: /, expires: 2026-03-20 12:00:00) [Secure]
```

## How It Works

### Chromium Browsers (Chrome, Edge, Chromium)

1. Locates browser data directories based on OS
2. Discovers profiles (Default, Profile 1, Profile 2, etc.)
3. Copies SQLite databases to temp files to avoid browser lock contention
4. Queries the relevant table (urls, autofill, or Bookmarks JSON file)
5. Cleans up temp files after extraction

### Firefox

1. Locates Firefox Profiles directory based on OS
2. Discovers profiles by scanning for directories containing `.default` (e.g., `abc123.default-release`)
3. Copies SQLite databases to temp files to avoid lock contention
4. Queries Firefox-specific tables:
   - History: `moz_places` in `places.sqlite`
   - Bookmarks: `moz_bookmarks` + `moz_places` in `places.sqlite`
   - Autofill: `moz_formhistory` in `formhistory.sqlite`
   - Cookies: `moz_cookies` in `cookies.sqlite` (plaintext values)
5. Firefox timestamps (PRTime) are microseconds since Unix epoch

### Windows Chromium Decryption (passwords, cookies)

1. Reads `Local State` JSON to extract the base64-encoded encryption key
2. Strips the "DPAPI" prefix and decrypts the AES key using `CryptUnprotectData`
3. For encrypted data: decrypts using AES-256-GCM with the recovered key

## Notes

- **Cross-platform:** History, autofill, and bookmarks work on Windows, macOS, and Linux for all browsers
- **Firefox cookies:** Plaintext on all platforms — no decryption needed
- **Chromium passwords/cookies:** Require DPAPI (Windows only, user-bound key decryption)
- The browser does not need to be closed — databases are copied to avoid lock conflicts
- Multi-profile support: Chromium (Default, Profile N), Firefox (*.default*)
- Supported browsers: Chrome, Edge, Chromium, Firefox
- History/autofill returns up to 500 most recent entries per profile
- Chrome timestamps use a custom epoch (microseconds since 1601-01-01 UTC); auto-detected
- Firefox passwords use NSS encryption and are not currently supported for decryption

## MITRE ATT&CK Mapping

- T1555.003 — Credentials from Password Stores: Credentials from Web Browsers
- T1217 — Browser Information Discovery
