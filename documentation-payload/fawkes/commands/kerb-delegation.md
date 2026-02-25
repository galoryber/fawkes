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

## Example Output

```
Kerberos Delegation Report
============================================================

Unconstrained Delegation (1 found, excluding DCs)
============================================================
Accounts with TrustedForDelegation can impersonate ANY user to ANY service.

[1] FILESERVER$ (computer)
    DN: CN=FILESERVER,CN=Computers,DC=corp,DC=local
    SPNs: cifs/fileserver.corp.local, HOST/fileserver.corp.local

Constrained Delegation (1 found)
============================================================
Accounts that can impersonate users to specific services.

[1] SVC-SQL$ (computer) [PROTOCOL TRANSITION]
    DN: CN=SVC-SQL,CN=Computers,DC=corp,DC=local
    Allowed services:
      - MSSQLSvc/dbserver.corp.local
      - MSSQLSvc/dbserver.corp.local:1433

Resource-Based Constrained Delegation (1 found)
============================================================
Objects where other accounts can impersonate users to their services.

[1] WEBSERVER$ (computer)
    DN: CN=WEBSERVER,CN=Computers,DC=corp,DC=local
    Allowed principals:
      - S-1-5-21-...-1105

Sensitive Accounts (NOT_DELEGATED) (2 found)
============================================================
These accounts have the NOT_DELEGATED flag — they CANNOT be impersonated via delegation.

[1] krbtgt
    DN: CN=krbtgt,CN=Users,DC=corp,DC=local
[2] Administrator
    DN: CN=Administrator,CN=Users,DC=corp,DC=local
```

## Delegation Attack Patterns

| Type | Risk | Attack |
|------|------|--------|
| Unconstrained | **Critical** | Any user authenticating to this server has their TGT cached. Attacker can extract TGTs and impersonate those users to any service. |
| Constrained | **High** | Account can impersonate users to listed services. With protocol transition, no user interaction needed (S4U2Self → S4U2Proxy). |
| RBCD | **High** | If you control an account listed in the RBCD ACL, you can impersonate any user to that target's services. |

## MITRE ATT&CK Mapping

- **T1550.003** — Use Alternate Authentication Material: Pass the Ticket
