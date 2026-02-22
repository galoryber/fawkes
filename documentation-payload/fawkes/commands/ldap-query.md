+++
title = "ldap-query"
chapter = false
weight = 104
hidden = false
+++

## Summary

Query Active Directory via LDAP with preset queries or custom filters. Uses the go-ldap pure Go library (no CGO required).

Supports authentication via explicit credentials (UPN format) or anonymous bind. Auto-detects the base DN from the domain controller's RootDSE.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `action` | Yes | `users` | Query type: `users`, `computers`, `groups`, `domain-admins`, `spns`, `asrep`, or `query` |
| `server` | Yes | | Domain controller IP or hostname |
| `filter` | No | | Custom LDAP filter (required when action=`query`) |
| `base_dn` | No | auto | LDAP search base (auto-detected from RootDSE) |
| `username` | No | | Bind username in UPN format (e.g., `user@domain.local`) |
| `password` | No | | Bind password |
| `port` | No | 389/636 | LDAP port (389 for LDAP, 636 for LDAPS) |
| `limit` | No | 100 | Maximum results to return |
| `use_tls` | No | false | Use LDAPS (TLS) instead of plain LDAP |

## Preset Queries

| Action | Filter | Description |
|--------|--------|-------------|
| `users` | `(&(objectCategory=person)(objectClass=user))` | All domain user accounts |
| `computers` | `(objectClass=computer)` | All domain-joined computers |
| `groups` | `(objectClass=group)` | All domain groups |
| `domain-admins` | Recursive `memberOf` with LDAP_MATCHING_RULE_IN_CHAIN | Domain admin accounts (recursive group membership) |
| `spns` | Users with `servicePrincipalName` set | Kerberoastable accounts |
| `asrep` | `DONT_REQUIRE_PREAUTH` flag (4194304) | AS-REP roastable accounts |

## Usage

```
# Enumerate domain users (requires valid credentials)
ldap-query -action users -server 192.168.1.10 -username user@domain.local -password Pass123

# Find domain admins
ldap-query -action domain-admins -server dc01.domain.local -username user@domain.local -password Pass123

# Find kerberoastable accounts
ldap-query -action spns -server 192.168.1.10 -username user@domain.local -password Pass123

# Find AS-REP roastable accounts
ldap-query -action asrep -server 192.168.1.10 -username user@domain.local -password Pass123

# Custom LDAP filter
ldap-query -action query -server 192.168.1.10 -username user@domain.local -password Pass123 -filter "(servicePrincipalName=*MSSQLSvc*)"

# Use LDAPS
ldap-query -action users -server 192.168.1.10 -username user@domain.local -password Pass123 -use_tls true
```

## Notes

- **Authentication**: Most AD environments require authenticated bind. Use UPN format (`user@domain.local`) for the username. The `DOMAIN\user` format is not supported for LDAP simple bind.
- **Paging**: Large result sets are automatically paged to avoid AD server limits.
- **Cross-platform**: Works from Windows, Linux, and macOS agents — only needs network access to the DC.

## MITRE ATT&CK Mapping

- **T1087.002** — Account Discovery: Domain Account
