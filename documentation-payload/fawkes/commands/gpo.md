+++
title = "gpo"
chapter = false
weight = 104
hidden = false
+++

## Summary

Enumerate Group Policy Objects (GPOs) via LDAP. List all GPOs, map GPO-to-OU links with enforcement status, and identify GPOs with interesting or potentially exploitable settings (scripts, scheduled tasks, security configurations, user/group management).

Cross-platform — works from Windows, Linux, and macOS agents.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | Yes | What to enumerate: `list`, `links`, `find`, or `all` |
| server | Yes | Domain Controller IP/hostname |
| username | No | LDAP bind username (UPN format: `user@domain.local`) |
| password | No | LDAP bind password |
| base_dn | No | LDAP base DN (auto-detected from RootDSE if not specified) |
| filter | No | Filter results by GPO display name (case-insensitive substring match) |
| port | No | LDAP port (default: 389, or 636 for LDAPS) |
| use_tls | No | Use LDAPS (TLS) connection (default: false) |

## Actions

### list
Enumerates all GPOs from `CN=Policies,CN=System,<baseDN>`. Shows display name, GUID, SYSVOL path, version (user/computer), status (enabled/disabled), and timestamps.

### links
Maps GPOs to the OUs, domains, and sites they are linked to. Parses the `gPLink` attribute across all AD objects and shows enforcement and disabled status for each link.

### find
Identifies GPOs with potentially interesting Client-Side Extension (CSE) settings. Categorizes findings into:
- **Scripts & Execution** — Startup/shutdown/logon/logoff scripts
- **Security Configuration** — Security settings, audit policies
- **Scheduled Tasks** — GPO-deployed scheduled tasks (Preferences)
- **User & Group Management** — Local users and groups (Preferences)
- **Credential & Certificate** — EFS recovery, IP Security
- **Network Configuration** — Firewall, wireless, VPN, NAP
- **Software Deployment** — Software installation policies
- **Other** — Registry, environment variables, drive mappings, data sources, shares

### all
Runs all three actions (list + links + find) in a single query.

## Usage

### List all GPOs in a domain
```
gpo -action list -server dc01 -username user@corp.local -password Pass123
```

### Map GPO links with enforcement
```
gpo -action links -server 192.168.1.1 -username admin@corp.local -password Admin1
```

### Find interesting GPO settings
```
gpo -action find -server dc01 -username user@corp.local -password Pass1
```

### Full enumeration (all actions)
```
gpo -action all -server dc01 -username user@corp.local -password Pass1
```

### Filter GPOs by name
```
gpo -action list -server dc01 -username user@corp.local -password Pass1 -filter "Default"
```

### LDAPS connection
```
gpo -action all -server dc01 -username user@corp.local -password Pass1 -use_tls true
```

## Output

### List Action
```
[*] Group Policy Objects (3 found)
------------------------------------------------------------

  [GPO] Default Domain Policy
    GUID:       {31B2F340-016D-11D2-945F-00C04FB984F9}
    SYSVOL:     \\north.sevenkingdoms.local\sysvol\...
    Version:    User=0, Computer=3
    Status:     Enabled
    Created:    2024-08-05 09:16:42 UTC
    Modified:   2024-11-20 10:37:52 UTC
```

### Links Action
```
[*] GPO Links (3 GPOs linked)
------------------------------------------------------------

  [GPO] Default Domain Policy {31B2F340-016D-11D2-945F-00C04FB984F9}
    → DC=north,DC=sevenkingdoms,DC=local
  [GPO] ansible-laps {GUID}
    → DC=essos,DC=local [ENFORCED]
```

### Find Action
```
[*] Interesting GPO Settings (4 findings)
------------------------------------------------------------

  [Security Configuration]
    Default Domain Policy
      GUID: {31B2F340-016D-11D2-945F-00C04FB984F9}
      CSE:  Security Settings

  [Software Deployment]
    Default Domain Policy
      GUID: {31B2F340-016D-11D2-945F-00C04FB984F9}
      CSE:  Software Installation
```

## OPSEC Considerations

- Uses standard LDAP queries against CN=Policies,CN=System — standard AD enumeration traffic
- Authenticated bind required for most AD configurations
- Base DN auto-detected via RootDSE query if not specified
- No modifications to AD objects — read-only enumeration
- GPO link enumeration queries across the entire directory tree (gPLink attribute)
- 10-second connection timeout prevents indefinite hangs against unreachable targets

## MITRE ATT&CK Mapping

- T1615 — Group Policy Discovery
