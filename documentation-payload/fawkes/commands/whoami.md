+++
title = "whoami"
chapter = false
weight = 107
hidden = false
+++

## Summary

Display the current user identity and security context.

On Windows, shows detailed information including username, SID, token type (primary vs impersonation), integrity level, and a full privilege enumeration. Reflects impersonation status from `make-token` or `steal-token`.

On Linux/macOS, shows username, UID, GID, home directory, and detects SUID elevation.

### Arguments

No arguments required.

## Usage
```
whoami
```

### Example Output (Windows)
```
User:        DESKTOP-ABC\setup
SID:         S-1-5-21-1234567890-1234567890-1234567890-1001
Token:       Primary (process)
Integrity:   Medium (S-1-16-8192)

Privileges:
  SeShutdownPrivilege                      Disabled
  SeChangeNotifyPrivilege                  Enabled (Default)
  SeUndockPrivilege                        Disabled
  SeIncreaseWorkingSetPrivilege            Disabled
  SeTimeZonePrivilege                      Disabled
```

### Example Output (Windows, impersonating)
```
User:        DOMAIN\admin
SID:         S-1-5-21-1234567890-1234567890-1234567890-500
Token:       Impersonation (thread)
Impersonating: Yes
Integrity:   High (S-1-16-12288)

Privileges:
  SeDebugPrivilege                         Enabled
  ...
```

## MITRE ATT&CK Mapping

- T1033 — System Owner/User Discovery
