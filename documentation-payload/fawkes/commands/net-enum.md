+++
title = "net-enum"
chapter = false
weight = 47
hidden = false
+++

## Summary

Cross-platform network enumeration command. Consolidates user/group enumeration, logged-on users, SMB sessions, share discovery, and domain information into a single command with action dispatch. Windows uses direct Win32 API calls (netapi32.dll, mpr.dll). Linux uses /etc/passwd, /etc/group, utmp, and config file parsing. macOS uses dscl (Directory Services), who, and sharing commands.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | Yes | Enumeration action (see table below) |
| target | No | Remote hostname or IP (blank = local machine). Windows only for remote queries. |
| group | No | Group name for `groupmembers` and `admins` actions |
| timeout | No | Timeout in seconds for remote operations (default: 30, Windows only) |

### Actions

| Action | Windows | Linux | macOS | Description |
|--------|---------|-------|-------|-------------|
| `users` | NetUserEnum | /etc/passwd | dscl /Users | List local user accounts with UID/GID |
| `groups` / `localgroups` | NetLocalGroupEnum | /etc/group | dscl /Groups | List local groups |
| `groupmembers` | NetLocalGroupGetMembers | /etc/group + passwd | dscl GroupMembership | List members of a specific group |
| `admins` | Administrators group | root/sudo/wheel groups | admin/wheel groups | List admin/privileged users |
| `sessions` / `loggedon` | NetWkstaUserEnum / NetSessionEnum | utmp parsing | who command | List logged-on users and sessions |
| `shares` | NetShareEnum | /etc/exports + smb.conf | /etc/exports + sharing -l | List NFS exports and SMB/Samba shares |
| `domainusers` | NetUserEnum (via DC) | N/A | N/A | List domain user accounts (Windows only) |
| `domaingroups` | NetGroupEnum (via DC) | N/A | N/A | List domain groups (Windows only) |
| `domaininfo` | DsGetDcNameW + trusts | N/A | N/A | Domain controller, account policy, trusts (Windows only) |
| `mapped` | WNetEnumResource | N/A | N/A | List mapped network drives (Windows only) |

## Usage

### Cross-Platform (Windows, Linux, macOS)
```
net-enum -action users
net-enum -action groups
net-enum -action groupmembers -group sudo
net-enum -action admins
net-enum -action sessions
net-enum -action shares
```

### Windows-Only
```
net-enum -action localgroups -target DC01
net-enum -action admins -target DC01
net-enum -action domainusers
net-enum -action domaingroups
net-enum -action domaininfo
net-enum -action loggedon -target FILESERVER
net-enum -action sessions -target DC01
net-enum -action shares -target DC01
net-enum -action mapped
```

## Platform Details

### Linux
- **users**: Parses /etc/passwd, includes UID, GID, home directory, shell. Classifies system users (UID < 1000).
- **groups**: Parses /etc/group with member counts.
- **groupmembers**: Combines /etc/group members + primary GID matching from /etc/passwd.
- **admins**: Checks root, sudo, wheel, and admin group membership.
- **sessions**: Binary utmp parsing from /var/run/utmp for logged-in users.
- **shares**: NFS exports from /etc/exports, Samba shares from /etc/samba/smb.conf.

### macOS
- **users**: dscl /Users with UID, filters system accounts (UID < 500 and _ prefix).
- **groups**: dscl /Groups with PrimaryGroupID.
- **groupmembers**: dscl GroupMembership for specified group.
- **admins**: admin + wheel group membership (deduplicated).
- **sessions**: who command output parsing.
- **shares**: NFS /etc/exports + sharing -l command.

## MITRE ATT&CK Mapping

- **T1087.001** — Account Discovery: Local Account
- **T1087.002** — Account Discovery: Domain Account
- **T1069.001** — Permission Groups Discovery: Local Groups
- **T1069.002** — Permission Groups Discovery: Domain Groups
- **T1033** — System Owner/User Discovery (sessions/loggedon)
- **T1049** — System Network Connections Discovery (sessions)
- **T1135** — Network Share Discovery (shares)
