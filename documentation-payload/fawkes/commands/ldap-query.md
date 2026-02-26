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
| `action` | Yes | `users` | Query type: `users`, `computers`, `groups`, `domain-admins`, `spns`, `asrep`, `dacl`, or `query` |
| `server` | Yes | | Domain controller IP or hostname |
| `filter` | No | | Custom LDAP filter (required when action=`query`). For `dacl`, specify target object name. |
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
| `dacl` | N/A | Parse DACL of a specific AD object (use `-filter` for target name) |

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

# Enumerate DACL permissions on a specific object
ldap-query -action dacl -server dc01 -filter "arya.stark" -username user@domain.local -password Pass123

# DACL on a group (find who can modify membership)
ldap-query -action dacl -server dc01 -filter "Domain Admins" -username user@domain.local -password Pass123

# Custom LDAP filter
ldap-query -action query -server 192.168.1.10 -username user@domain.local -password Pass123 -filter "(servicePrincipalName=*MSSQLSvc*)"

# Use LDAPS
ldap-query -action users -server 192.168.1.10 -username user@domain.local -password Pass123 -use_tls true
```

## Example Output

**dacl action:**
```
[*] DACL Enumeration (T1069)
[+] Target: CN=arya.stark,CN=Users,DC=north,DC=sevenkingdoms,DC=local
[+] Object Class: top, person, organizationalPerson, user
[+] ACE Count: 51
[+] Owner: Domain Admins
------------------------------------------------------------

=== DANGEROUS PERMISSIONS (attack targets) ===
[!]   Authenticated Users                      GenericAll (FULL CONTROL)

=== NOTABLE PERMISSIONS ===
[*]   Key Admins                               WriteProperty(msDS-KeyCredentialLink), ReadProperty
[*]   Enterprise Key Admins                    WriteProperty(msDS-KeyCredentialLink), ReadProperty
[*]   Self                                     WriteProperty(msDS-AllowedToActOnBehalfOfOtherIdentity)

=== STANDARD PERMISSIONS ===
      Domain Admins                            StandardAll, AllExtendedRights, ...
```

## DACL Action Details

The `dacl` action parses the `nTSecurityDescriptor` binary attribute and:

- **Categorizes ACEs** as Dangerous, Notable, or Standard based on access mask and principal
- **Resolves SIDs** to human-readable names via LDAP reverse lookup
- **Maps GUIDs** to known AD attributes/extended rights (msDS-KeyCredentialLink, msDS-AllowedToActOnBehalfOfOtherIdentity, User-Force-Change-Password, etc.)
- **Highlights attack vectors**: GenericAll, GenericWrite, WriteDACL, WriteOwner, WriteProperty on sensitive attributes

Use this to identify RBCD targets, Shadow Credentials targets, or any object where non-privileged accounts have excessive permissions.

## Notes

- **Authentication**: Most AD environments require authenticated bind. Use UPN format (`user@domain.local`) for the username. The `DOMAIN\user` format is not supported for LDAP simple bind.
- **Paging**: Large result sets are automatically paged to avoid AD server limits.
- **Cross-platform**: Works from Windows, Linux, and macOS agents — only needs network access to the DC.
- **DACL permissions**: The returned DACL depends on the bind account's privileges. Some ACEs may not be visible without elevated permissions.

## MITRE ATT&CK Mapping

- **T1087.002** — Account Discovery: Domain Account
- **T1069.002** — Permission Groups Discovery: Domain Groups
