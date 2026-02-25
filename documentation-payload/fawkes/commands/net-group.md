+++
title = "net-group"
chapter = false
weight = 117
hidden = false
+++

## Summary

Enumerate Active Directory group memberships via LDAP. Supports listing all domain groups, querying recursive group members, reverse-looking up a user's group memberships, and enumerating all privileged group members. Uses `LDAP_MATCHING_RULE_IN_CHAIN` for recursive membership resolution.

Cross-platform — works on Windows, Linux, and macOS.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | privileged | `list`, `members`, `user`, or `privileged` |
| server | Yes | | Domain controller IP or hostname |
| group | No* | | Group name (required for `members` action) |
| user | No* | | sAMAccountName (required for `user` action) |
| username | No | | LDAP bind username (user@domain format) |
| password | No | | LDAP bind password |
| port | No | 389 | LDAP port |
| use_tls | No | false | Use LDAPS (port 636) |

## Actions

| Action | Description |
|--------|-------------|
| `privileged` | Enumerate members of 11 privileged groups (Domain Admins, Enterprise Admins, etc.) |
| `members` | List all members of a specific group (recursive, categorized by type) |
| `user` | Find all groups a user belongs to (recursive, highlights privileged groups) |
| `list` | List all domain groups with member counts, group type, and description |

## Usage

```
# Enumerate privileged group members
net-group -action privileged -server 192.168.1.10 -username user@domain.local -password Pass123

# List members of a specific group (recursive)
net-group -action members -server dc01 -group "Domain Admins" -username user@domain -password pass

# Find all groups a user belongs to
net-group -action user -server dc01 -user jon.snow -username user@domain -password pass

# List all domain groups
net-group -action list -server dc01 -username user@domain -password pass
```

## Example Output — Privileged Groups

```
Privileged Group Enumeration — north.sevenkingdoms.local
============================================================

Domain Admins (2 members)
--------------------------------------------------
  - eddard.stark (user)
  - Administrator (user)

Administrators (7 members)
--------------------------------------------------
  - Domain Admins (group)
  - eddard.stark (user)
  - catelyn.stark (user)
  - robb.stark (user)
  - Administrator (user)
  - vagrant (user)
  - cloudbase-init (user)

Total privileged accounts: 9
```

## Example Output — User Groups

```
Group Memberships for "jon.snow" — 3 groups
============================================================

Other Groups (3):
  - Night Watch  [Global Security]
  - Remote Desktop Users  [Domain Local Security]
  - Stark  [Global Security]
```

## Privileged Groups Checked

| Group | Risk |
|-------|------|
| Domain Admins | Full domain control |
| Enterprise Admins | Full forest control |
| Schema Admins | Can modify AD schema |
| Administrators | Local admin on DCs |
| Account Operators | Can create/modify users and groups |
| Backup Operators | Can read any file (backup privilege) |
| Server Operators | Can manage domain servers |
| Print Operators | Can load drivers on DCs |
| DnsAdmins | Can load DLL via DNS service (privilege escalation) |
| Group Policy Creator Owners | Can create/modify GPOs |
| Cert Publishers | Can publish certificates to AD |

## OPSEC

- Uses LDAP queries with `LDAP_MATCHING_RULE_IN_CHAIN` OID for recursive membership
- Multiple LDAP queries for privileged action (one per group)
- Single query for members/user actions
- May be logged if "Audit Directory Service Access" is enabled

## MITRE ATT&CK Mapping

- **T1069.002** — Permission Groups Discovery: Domain Groups
