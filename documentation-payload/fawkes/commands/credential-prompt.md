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

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| title | No | "Windows Security" (Win) / "Update Required" (macOS) | Dialog title bar text |
| message | No | "Enter your credentials to continue." (Win) / "macOS needs your password to apply system updates." (macOS) | Body text displayed in the dialog |
| icon | No | caution | Dialog icon (macOS only): caution, note, or stop |

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

### Both Platforms
- Cancel detection: user clicking Cancel returns success status with "User cancelled" message
- Empty password submissions are detected and reported
- Credentials are automatically stored in Mythic's credential vault as plaintext

## MITRE ATT&CK Mapping

- **T1056.002** — Input Capture: GUI Input Capture
