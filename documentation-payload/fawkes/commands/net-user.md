+++
title = "net-user"
chapter = false
weight = 155
hidden = false
+++

## Summary

Manage local user accounts and group membership via Win32 netapi32.dll API. Create users, delete users, change passwords, query account details, and manage local group membership — all without spawning `net.exe` (opsec-friendly).

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `-action` | Yes | Action to perform: `add`, `delete`, `info`, `password`, `group-add`, `group-remove` |
| `-username` | Yes | Target username |
| `-password` | For add/password | Account password |
| `-group` | For group-add/group-remove | Local group name |
| `-comment` | No | Account description (for add action) |

## Usage

### Create a new local user
```
net-user -action add -username backdoor -password "S3cure!P@ss" -comment "Backup admin"
```

### Get user info
```
net-user -action info -username setup
```

### Change a user's password
```
net-user -action password -username backdoor -password "N3w!P@ss"
```

### Add user to Administrators group
```
net-user -action group-add -username backdoor -group Administrators
```

### Remove user from a group
```
net-user -action group-remove -username backdoor -group "Remote Desktop Users"
```

### Delete a user
```
net-user -action delete -username backdoor
```

## Example Output

### Info
```
User: setup
Full Name: setup
Privilege: Administrator
Flags: Enabled, Password Never Expires
Password Age: 45 days
Bad Password Count: 0
Number of Logons: 127
Last Logon: 1740268800 (Unix timestamp)
Logon Server: \\WIN1123H2
Primary Group ID: 513
```

## How It Works

All operations use **netapi32.dll Win32 API** — no subprocess creation, no `net.exe`:

| Action | API Call |
|--------|----------|
| add | `NetUserAdd` (level 1) |
| delete | `NetUserDel` |
| info | `NetUserGetInfo` (level 4) |
| password | `NetUserSetInfo` (level 1003) |
| group-add | `NetLocalGroupAddMembers` (level 3) |
| group-remove | `NetLocalGroupDelMembers` (level 3) |

New accounts are created with `UF_SCRIPT | UF_NORMAL_ACCOUNT | UF_DONT_EXPIRE_PASSWD` flags.

## Operational Notes

- **Requires administrator privileges** for all write operations (add, delete, password, group-add, group-remove)
- The `info` action works at any privilege level for local accounts
- Account creation uses `USER_PRIV_USER` (standard user) — add to Administrators group separately for admin access
- No process creation artifacts (no `net.exe`, `net1.exe`) — only API calls logged
- Common error codes: 2221 (user not found), 2224 (user already exists), 2220 (group not found), 1378 (already a member), 5 (access denied)

## MITRE ATT&CK Mapping

- **T1136.001** — Create Account: Local Account
- **T1098** — Account Manipulation
