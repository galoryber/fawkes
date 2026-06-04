+++
title = "browser"
chapter = false
weight = 25
hidden = false
+++

## Summary

Harvest browser data from Chromium-based browsers (Chrome, Edge, Chromium) and Firefox. Cross-platform support for browsing history, autofill form data, bookmarks, passwords, and cookies on all platforms (Windows, macOS, Linux). Windows uses DPAPI + AES-GCM decryption for Chromium credentials and cookies, macOS uses Keychain, and Linux uses GNOME Keyring / KWallet for Chromium decryption. Firefox cookies are plaintext on all platforms.

### Platform Support

| Action | Windows (Chromium) | Windows (Firefox) | macOS (Chromium) | macOS (Firefox) | macOS (Safari) | Linux (Chromium) | Linux (Firefox) |
|--------|-------------------|-------------------|-----------------|----------------|----------------|-----------------|----------------|
| passwords | Yes (DPAPI) | Yes (key4.db) | Yes (Keychain) | Yes (key4.db) | Yes (Keychain) | Yes (GNOME Keyring/KWallet) | Yes (key4.db) |
| cookies | Yes (DPAPI) | Yes (plaintext) | Yes (Keychain) | Yes (plaintext) | Yes (GNOME Keyring/KWallet) | Yes (plaintext) |
| history | Yes | Yes | Yes | Yes | Yes | Yes |
| autofill | Yes | Yes | Yes | Yes | Yes | Yes |
| bookmarks | Yes | Yes | Yes | Yes | Yes | Yes |
| downloads | Yes | Yes | Yes | Yes | Yes | Yes |

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| action | choose_one | No | history | `passwords` — saved login credentials (all platforms: DPAPI on Windows, Keychain on macOS, GNOME Keyring/KWallet on Linux — Chromium only); `cookies` — session cookies (all platforms: Chromium via platform keystore decryption; Firefox plaintext); `history` — browsing history; `autofill` — form data; `bookmarks` — saved URLs; `downloads` — download history |
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

### Harvest Download History

Extract recent download history (file paths, URLs, sizes, states):
```
browser -action downloads
```

### Harvest Credentials (All Platforms)

Extract saved passwords from Chromium browsers, Firefox (key4.db decryption), and Safari (macOS Keychain):
```
browser -action passwords
```

### Harvest Cookies

Extract Firefox cookies (all platforms, plaintext):
```
browser -action cookies -browser firefox
```

Extract Chromium cookies (all platforms — decrypted via platform keystore):
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
   - Downloads: `downloads.json` (plaintext JSON with source URLs, file paths, sizes)
   - Passwords: `logins.json` entries decrypted via `key4.db` master key
5. Firefox timestamps (PRTime) are microseconds since Unix epoch

### Firefox Password Decryption

1. Opens `key4.db` (NSS key store) from the Firefox profile
2. Reads the global salt from the `metadata` table
3. Verifies the master password (default: empty) against the `password-check` entry
4. Extracts the encrypted master key from the `nssPrivate` table
5. Decrypts the master key using PBES2 (PBKDF2-HMAC-SHA256 + AES-256-CBC) or legacy PBE-SHA1-3DES
6. Uses the 24-byte master key to decrypt individual login entries from `logins.json` via 3DES-CBC
7. Decrypted credentials are registered in the Mythic credential vault

### Safari (macOS only)

1. Enumerates internet passwords from the macOS login Keychain via `security dump-keychain`
2. Filters for `inet` class items (internet passwords stored by Safari)
3. Extracts server, account, protocol, and port from each Keychain entry
4. Attempts to retrieve actual passwords via `security find-internet-password -g`
5. Password retrieval may require an unlocked Keychain or trigger a user prompt

### Chromium Decryption (passwords, cookies — all platforms)

- **Windows**: Reads `Local State` JSON, strips the "DPAPI" prefix, decrypts the AES key using `CryptUnprotectData`, then decrypts data using AES-256-GCM
- **macOS**: Reads `Local State` JSON, retrieves the decryption key from the macOS Keychain (`Chrome Safe Storage`), derives the AES key via PBKDF2, then decrypts data using AES-128-CBC
- **Linux**: Reads `Local State` JSON, retrieves the decryption key from GNOME Keyring or KWallet (`Chrome Safe Storage`), derives the AES key via PBKDF2, then decrypts data using AES-128-CBC

## Notes

- **Cross-platform:** All actions (history, autofill, bookmarks, downloads, passwords, cookies) work on Windows, macOS, and Linux
- **Firefox cookies:** Plaintext on all platforms — no decryption needed
- **Chromium passwords/cookies:** Decrypted via platform-specific keystores (DPAPI on Windows, Keychain on macOS, GNOME Keyring/KWallet on Linux)
- The browser does not need to be closed — databases are copied to avoid lock conflicts
- Multi-profile support: Chromium (Default, Profile N), Firefox (*.default*)
- Supported browsers: Chrome, Edge, Chromium, Firefox
- History/autofill returns up to 500 most recent entries per profile
- Chrome timestamps use a custom epoch (microseconds since 1601-01-01 UTC); auto-detected
- Firefox passwords are decrypted via NSS key4.db (no master password required if none was set)
- Safari passwords (macOS) are extracted from the login Keychain — password retrieval requires an unlocked Keychain

## MITRE ATT&CK Mapping

- T1555.003 — Credentials from Password Stores: Credentials from Web Browsers
- T1217 — Browser Information Discovery
