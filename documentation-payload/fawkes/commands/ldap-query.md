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
| `action` | Yes | `users` | Query type: `users`, `computers`, `groups`, `domain-admins`, `spns`, `asrep`, `admins`, `disabled`, `gpo`, `ou`, `password-never-expires`, `trusts`, `unconstrained`, `constrained`, `dacl`, `gmsa`, or `query` |
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
| `admins` | `adminCount=1` | All administrative accounts (flagged by AD — Domain Admins, Enterprise Admins, Schema Admins, Account Operators, etc.) |
| `disabled` | `ACCOUNTDISABLE` flag (2) | Disabled user accounts |
| `gpo` | `(objectClass=groupPolicyContainer)` | Group Policy Objects with SYSVOL paths |
| `ou` | `(objectClass=organizationalUnit)` | Organizational Units (AD structure mapping) |
| `password-never-expires` | `DONT_EXPIRE_PASSWORD` flag (65536) | Accounts with password never expires policy |
| `trusts` | `(objectClass=trustedDomain)` | Domain trust relationships (partner, direction, type) |
| `unconstrained` | `TRUSTED_FOR_DELEGATION` flag (524288), excluding DCs | Computers with unconstrained delegation |
| `constrained` | `(msDS-AllowedToDelegateTo=*)` | Accounts with constrained delegation |
| `dacl` | N/A | Parse DACL of a specific AD object (use `-filter` for target name) |
| `gmsa` | `(objectClass=msDS-GroupManagedServiceAccount)` | Enumerate Group Managed Service Accounts. Extracts NTLM hash from msDS-ManagedPassword if readable. Identifies who can read the password. |

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

# Find all administrative accounts (adminCount=1)
ldap-query -action admins -server 192.168.1.10 -username user@domain.local -password Pass123

# Find disabled accounts
ldap-query -action disabled -server 192.168.1.10 -username user@domain.local -password Pass123

# Enumerate Group Policy Objects
ldap-query -action gpo -server 192.168.1.10 -username user@domain.local -password Pass123

# Map Organizational Units
ldap-query -action ou -server 192.168.1.10 -username user@domain.local -password Pass123

# Find accounts with password never expires
ldap-query -action password-never-expires -server 192.168.1.10 -username user@domain.local -password Pass123

# Enumerate domain trust relationships
ldap-query -action trusts -server 192.168.1.10 -username user@domain.local -password Pass123

# Find computers with unconstrained delegation (TGT forwarding)
ldap-query -action unconstrained -server 192.168.1.10 -username user@domain.local -password Pass123

# Find accounts with constrained delegation
ldap-query -action constrained -server 192.168.1.10 -username user@domain.local -password Pass123

# Enumerate DACL permissions on a specific object
ldap-query -action dacl -server dc01 -filter "arya.stark" -username user@domain.local -password Pass123

# DACL on a group (find who can modify membership)
ldap-query -action dacl -server dc01 -filter "Domain Admins" -username user@domain.local -password Pass123

# Enumerate gMSA accounts and extract NTLM hashes (if readable)
ldap-query -action gmsa -server dc01 -username user@domain.local -password Pass123

# Custom LDAP filter
ldap-query -action query -server 192.168.1.10 -username user@domain.local -password Pass123 -filter "(servicePrincipalName=*MSSQLSvc*)"

# Use LDAPS
ldap-query -action users -server 192.168.1.10 -username user@domain.local -password Pass123 -use_tls true
```

## Output Format

### Regular Queries (users, computers, groups, etc.)
Returns a JSON object rendered as a sortable table via browser script:

```json
{
  "query": "All domain users",
  "base_dn": "DC=north,DC=sevenkingdoms,DC=local",
  "filter": "(&(objectCategory=person)(objectClass=user))",
  "count": 15,
  "entries": [
    {"dn": "CN=arya.stark,CN=Users,DC=...", "sAMAccountName": "arya.stark", "mail": "arya@north.sevenkingdoms.local", ...}
  ]
}
```

Columns are auto-detected from the LDAP attributes present in the result set. Priority attributes (sAMAccountName, cn, displayName) appear first.

### DACL Query
Returns a JSON object with ACE entries rendered as a risk-colored table:

```json
{
  "mode": "dacl",
  "target": "CN=arya.stark,CN=Users,DC=...",
  "object_class": "top, person, organizationalPerson, user",
  "ace_count": 51,
  "owner": "Domain Admins",
  "dangerous": 1,
  "notable": 3,
  "aces": [
    {"principal": "Authenticated Users", "permissions": "GenericAll (FULL CONTROL)", "risk": "dangerous", "sid": "S-1-5-11"},
    {"principal": "Key Admins", "permissions": "WriteProperty(msDS-KeyCredentialLink), ReadProperty", "risk": "notable", "sid": "S-1-5-21-..."}
  ]
}
```

Dangerous ACEs are highlighted red, notable ACEs orange. Risk assessment considers the principal (low-priv accounts with write permissions = dangerous).

## DACL Action Details

The `dacl` action parses the `nTSecurityDescriptor` binary attribute and:

- **Categorizes ACEs** as Dangerous, Notable, or Standard based on access mask and principal
- **Resolves SIDs** to human-readable names via LDAP reverse lookup
- **Maps GUIDs** to known AD attributes/extended rights (msDS-KeyCredentialLink, msDS-AllowedToActOnBehalfOfOtherIdentity, User-Force-Change-Password, etc.)
- **Highlights attack vectors**: GenericAll, GenericWrite, WriteDACL, WriteOwner, WriteProperty on sensitive attributes

Use this to identify RBCD targets, Shadow Credentials targets, or any object where non-privileged accounts have excessive permissions.

## gMSA Action Details

The `gmsa` action enumerates Group Managed Service Accounts and attempts to extract their NTLM password hashes:

- **Enumerates all gMSA accounts** in the domain
- **Reads msDS-ManagedPassword** binary blob (requires appropriate ACL permissions)
- **Parses MSDS-MANAGEDPASSWORD_BLOB** (MS-ADTS Section 2.2.17) to extract the current password
- **Computes NTLM hash** (MD4 of UTF-16LE password) for pass-the-hash use
- **Identifies allowed principals** by parsing msDS-GroupMSAMembership security descriptor
- **Registers extracted hashes** in the Mythic credential vault automatically

This is a common AD privilege escalation path: any principal allowed to read `msDS-ManagedPassword` can extract the NTLM hash and use it for authentication via pass-the-hash.

## Notes

- **Authentication**: Most AD environments require authenticated bind. Use UPN format (`user@domain.local`) for the username. The `DOMAIN\user` format is not supported for LDAP simple bind.
- **Paging**: Large result sets are automatically paged to avoid AD server limits.
- **Cross-platform**: Works from Windows, Linux, and macOS agents — only needs network access to the DC.
- **DACL permissions**: The returned DACL depends on the bind account's privileges. Some ACEs may not be visible without elevated permissions.

## MITRE ATT&CK Mapping

- **T1087.002** — Account Discovery: Domain Account
- **T1069.002** — Permission Groups Discovery: Domain Groups
- **T1482** — Domain Trust Discovery
- **T1555** — Credentials from Password Stores (gMSA)
- **T1003** — OS Credential Dumping (gMSA)
