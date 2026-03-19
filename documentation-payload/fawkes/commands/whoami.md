+++
title = "whoami"
chapter = false
weight = 107
hidden = false
+++

## Summary

Display the current user identity and security context.

On Windows, shows detailed information including username, SID, token type (primary vs impersonation), integrity level, and a full privilege enumeration. Reflects impersonation status from `make-token` or `steal-token`.

On Linux, shows username, UID, GID, home directory, SUID detection, effective capabilities (decoded to human-readable names), SELinux/AppArmor security context, and container detection (Docker, Kubernetes, LXC).

On macOS, shows username, UID, GID, home directory, and SUID detection.

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

### Example Output (Linux)
```
Host:     web-server-01
User:     www-data
UID:      33
GID:      33
Home:     /var/www

Groups:
  www-data (gid=33)

Effective Capabilities (3):
  CAP_CHOWN
  CAP_NET_BIND_SERVICE
  CAP_SETUID

SELinux:  system_u:system_r:httpd_t:s0

Container: Docker
```

### Example Output (Linux, root)
```
Host:     target-01
User:     root
UID:      0
GID:      0
Home:     /root
Privilege: root

Groups:
  root (gid=0)

Capabilities: FULL (all capabilities — root-equivalent)
```

## MITRE ATT&CK Mapping

- T1033 — System Owner/User Discovery
