+++
title = "kerb-delegation"
chapter = false
weight = 106
hidden = false
+++

## Summary

Enumerate Kerberos delegation relationships in Active Directory via LDAP. Identifies unconstrained delegation, constrained delegation (with protocol transition detection), and resource-based constrained delegation (RBCD) configurations that could be abused for lateral movement or privilege escalation.

Cross-platform — works on Windows, Linux, and macOS.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | | `all`, `unconstrained`, `constrained`, or `rbcd` |
| server | Yes | | Domain controller IP or hostname |
| username | No | | LDAP bind username (user@domain format) |
| password | No | | LDAP bind password |
| port | No | 389 | LDAP port |
| use_tls | No | false | Use LDAPS (port 636) |

## Actions

| Action | Description |
|--------|-------------|
| `unconstrained` | Find accounts with TrustedForDelegation (UAC 0x80000). Excludes domain controllers (primaryGroupID=516). |
| `constrained` | Find accounts with msDS-AllowedToDelegateTo set. Reports protocol transition (S4U2Self) capability. |
| `rbcd` | Find objects with msDS-AllowedToActOnBehalfOfOtherIdentity. Parses the security descriptor to show allowed principals. |
| `all` | Run all three checks plus sensitive account enumeration (NOT_DELEGATED flag). |

## Usage

```
# Enumerate all delegation in a domain
kerb-delegation -action all -server 192.168.1.10 -username admin@corp.local -password Pass123

# Check only unconstrained delegation
kerb-delegation -action unconstrained -server dc01.corp.local -username admin@corp.local -password Pass123

# Check constrained delegation with protocol transition
kerb-delegation -action constrained -server 192.168.1.10 -username admin@corp.local -password Pass123

# Check RBCD configurations
kerb-delegation -action rbcd -server 192.168.1.10 -username admin@corp.local -password Pass123
```

## Output Format

Returns a JSON array rendered as a sortable table via browser script:
```json
[
  {
    "account": "FILESERVER$",
    "dns": "fileserver.corp.local",
    "delegation_type": "Unconstrained",
    "spns": ["cifs/fileserver.corp.local", "HOST/fileserver.corp.local"],
    "risk": "TGT cached for any authenticating user"
  },
  {
    "account": "SVC-SQL$",
    "dns": "svc-sql.corp.local",
    "delegation_type": "Constrained",
    "mode": "Protocol Transition (S4U2Self)",
    "targets": ["MSSQLSvc/dbserver.corp.local", "MSSQLSvc/dbserver.corp.local:1433"],
    "s4u2self": true,
    "risk": "S4U2Self enabled — no user interaction needed"
  },
  {
    "account": "WEBSERVER$",
    "delegation_type": "RBCD",
    "targets": ["S-1-5-21-...-1105"]
  },
  {
    "account": "Administrator",
    "delegation_type": "Protected",
    "description": "NOT_DELEGATED — cannot be impersonated via delegation"
  }
]
```

The browser script highlights unconstrained delegation in red, S4U2Self-enabled constrained delegation in orange, protected accounts in green, and disabled accounts in gray. The `all` action combines results from all delegation types plus protected accounts.

## Delegation Attack Patterns

| Type | Risk | Attack |
|------|------|--------|
| Unconstrained | **Critical** | Any user authenticating to this server has their TGT cached. Attacker can extract TGTs and impersonate those users to any service. |
| Constrained | **High** | Account can impersonate users to listed services. With protocol transition, no user interaction needed (S4U2Self → S4U2Proxy). |
| RBCD | **High** | If you control an account listed in the RBCD ACL, you can impersonate any user to that target's services. |

## MITRE ATT&CK Mapping

- **T1550.003** — Use Alternate Authentication Material: Pass the Ticket
