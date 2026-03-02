+++
title = "credential-prompt"
chapter = false
weight = 219
hidden = false
+++

## Summary

{{% notice info %}}macOS Only{{% /notice %}}

Display a native macOS credential dialog to capture user passwords. Uses AppleScript's `display dialog` with a hidden answer field, presenting a legitimate-looking system prompt. Captured credentials are automatically reported to Mythic's credential vault.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| title | No | Update Required | Dialog title bar text |
| message | No | macOS needs your password to apply system updates. | Body text displayed in the dialog |
| icon | No | caution | Dialog icon: caution (warning triangle), note (info), or stop (critical) |

## Usage

```
# Default system update dialog
credential-prompt

# Custom title and message
credential-prompt -title "Keychain Access" -message "Your login keychain password is needed to continue."

# Critical-looking dialog
credential-prompt -title "Security Alert" -message "Verify your identity to proceed." -icon stop
```

### Example Output

```
=== Credential Prompt Result ===

User:     gary
Password: P@ssw0rd123
Dialog:   Keychain Access
```

## Operational Notes

- The dialog blocks until the user interacts (OK or Cancel)
- 5-minute timeout prevents indefinite waiting
- Cancel detection: user clicking Cancel returns a success status with "User cancelled" message
- Empty password submissions are detected and reported
- Credentials are automatically stored in Mythic's credential vault as plaintext
- The dialog appears as a native macOS system prompt — indistinguishable from legitimate dialogs
- Choose icons strategically: `caution` for updates/warnings, `note` for info/preferences, `stop` for security alerts
- Pair with `keychain` for password-protected keychain access after capturing credentials

## MITRE ATT&CK Mapping

- **T1056.002** — Input Capture: GUI Input Capture
