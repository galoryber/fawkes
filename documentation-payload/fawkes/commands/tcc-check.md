+++
title = "tcc-check"
chapter = false
weight = 220
hidden = false
+++

## Summary

{{% notice info %}}macOS Only{{% /notice %}}

Enumerate macOS Transparency, Consent, and Control (TCC) permissions. Reads the TCC SQLite database to discover which applications have been granted sensitive permissions like camera, microphone, screen recording, full disk access, accessibility, and more. Reports from both user-level and system-level databases.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| service | No | (all) | Filter by TCC service name (partial match). Examples: Camera, Microphone, ScreenCapture, SystemPolicyAllFiles |

## Usage

```
# Enumerate all TCC permissions
tcc-check

# Filter for camera permissions
tcc-check -service Camera

# Filter for screen recording
tcc-check -service ScreenCapture

# Filter for full disk access
tcc-check -service SystemPolicyAllFiles

# Filter for accessibility permissions
tcc-check -service Accessibility
```

### Example Output

```
=== macOS TCC Permissions ===

User DB:   /Users/gary/Library/Application Support/com.apple.TCC/TCC.db
System DB: /Library/Application Support/com.apple.TCC/TCC.db
Records:   12

--- Camera ---
  [Allowed] com.zoom.us  (Bundle ID, User Consent, user)
  [Allowed] com.apple.Terminal  (Bundle ID, User Consent, user)
  [Denied] com.google.Chrome  (Bundle ID, User Consent, user)

--- Screen Recording ---
  [Allowed] com.apple.Terminal  (Bundle ID, User Consent, system)
  [Denied] com.zoom.us  (Bundle ID, User Consent, system)

--- Full Disk Access ---
  [Allowed] /usr/sbin/sshd  (Absolute Path, System Set, system)
  [Allowed] com.apple.Terminal  (Bundle ID, User Consent, system)

=== Allowed Permissions Summary ===
  Camera: com.zoom.us (user)
  Camera: com.apple.Terminal (user)
  Screen Recording: com.apple.Terminal (system)
  Full Disk Access: /usr/sbin/sshd (system)
  Full Disk Access: com.apple.Terminal (system)
```

## Operational Notes

- **User DB** (`~/Library/Application Support/com.apple.TCC/TCC.db`) — readable by the current user, contains per-user consent decisions
- **System DB** (`/Library/Application Support/com.apple.TCC/TCC.db`) — requires Full Disk Access or root to read. If not accessible, only user-level permissions are shown
- Auth values: Allowed (2), Denied (0), Unknown (1), Limited (3)
- Auth reasons include: User Consent, System Set, MDM Policy, Service Policy, Entitled
- Client types: Bundle ID (app identifier) or Absolute Path (binary path)
- 40+ known TCC service mappings including Camera, Microphone, Screen Recording, Full Disk Access, Accessibility, Contacts, Calendar, Photos, Location, Input Monitoring, Endpoint Security
- Partial match filtering allows flexible queries (e.g., "Policy" matches SystemPolicyAllFiles, SystemPolicyDesktopFolder, etc.)
- The summary section highlights only allowed permissions for quick operational assessment
- Pair with `privesc-check` to understand the full security posture of the macOS target

## MITRE ATT&CK Mapping

- **T1082** — System Information Discovery
