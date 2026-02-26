+++
title = "laps"
chapter = false
weight = 124
hidden = false
+++

## Summary

Read LAPS (Local Administrator Password Solution) passwords from Active Directory via LDAP. Supports both legacy LAPS v1 (`ms-Mcs-AdmPwd`) and Windows LAPS v2 (`ms-LAPS-Password`).

LAPS automatically rotates local administrator passwords on domain-joined computers. Reading these passwords provides immediate local admin access to target machines.

Cross-platform — works on Windows, Linux, and macOS.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `-server` | Yes | Domain controller IP or hostname |
| `-username` | Yes | LDAP username (e.g., `user@domain.local`) |
| `-password` | Yes | LDAP password |
| `-filter` | No | Filter by computer name (substring match) |
| `-use_tls` | No | Use LDAPS (port 636) instead of LDAP (port 389) |

## Usage

### Read all LAPS passwords
```
laps -server 192.168.1.1 -username admin@corp.local -password Pass123
```

### Filter by computer name
```
laps -server dc01 -username admin@corp.local -password Pass123 -filter srv
```

### Use LDAPS
```
laps -server dc01.corp.local -username admin@corp.local -password Pass123 -use_tls true
```

## Output

For each computer with readable LAPS passwords:
- Computer name and FQDN
- Operating system
- **LAPS v1**: Plaintext password, expiration time with countdown
- **LAPS v2**: Managed account name, plaintext password, update timestamp, expiration
- **LAPS v2 Encrypted**: Reports encrypted password presence (requires DPAPI backup key)

If no results are found, the command reports possible reasons (LAPS not deployed, insufficient permissions, or no matching computers).

## OPSEC Considerations

- Uses standard LDAP queries — same as legitimate admin tools
- Does not modify any AD objects (read-only)
- LDAP bind generates logon events on the DC (Event ID 4624)
- Querying LAPS attributes may be logged by advanced monitoring solutions
- Password read access is typically delegated per-OU — a standard user won't see passwords

## MITRE ATT&CK Mapping

- **T1552.006** — Unsecured Credentials: Group Policy Preferences
