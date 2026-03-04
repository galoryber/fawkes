+++
title = "net-enum"
chapter = false
weight = 47
hidden = false
+++

## Summary

Unified Windows network enumeration command using direct Win32 API calls. Consolidates user/group enumeration, logged-on users, SMB sessions, share discovery, and domain information into a single command with action dispatch. No subprocess creation — all operations run in-process via netapi32.dll and mpr.dll.

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | Yes | Enumeration action (see table below) |
| target | No | Remote hostname or IP (blank = local machine). For `groupmembers`: also used as group name if `-group` not set. |
| group | No | Group name for `groupmembers` and `admins` actions (e.g., Administrators, "Remote Desktop Users") |

### Actions

| Action | API Used | Description |
|--------|----------|-------------|
| `users` | NetUserEnum | List local user accounts |
| `localgroups` | NetLocalGroupEnum | List local groups (supports remote via -target) |
| `groupmembers` | NetLocalGroupGetMembers | List members of a group with SID type info |
| `admins` | NetLocalGroupGetMembers | Shortcut: members of Administrators group |
| `domainusers` | NetUserEnum (via DC) | List domain user accounts |
| `domaingroups` | NetGroupEnum (via DC) | List domain groups |
| `domaininfo` | DsGetDcNameW + DsEnumerateDomainTrustsW | Domain controller, account policy, trusts |
| `loggedon` | NetWkstaUserEnum | List logged-on users with domain and logon server |
| `sessions` | NetSessionEnum | List active SMB sessions (level 502/10 fallback) |
| `shares` | NetShareEnum | List shares (local if no target, remote if target set) |
| `mapped` | WNetEnumResource | List mapped network drives |

## Usage

### User & Group Enumeration
```
net-enum -action users
net-enum -action localgroups
net-enum -action localgroups -target DC01
net-enum -action groupmembers -group Administrators
net-enum -action groupmembers -group "Remote Desktop Users" -target SRV01
net-enum -action admins
net-enum -action admins -target DC01
```

### Domain Enumeration
```
net-enum -action domainusers
net-enum -action domaingroups
net-enum -action domaininfo
```

### Network Enumeration
```
net-enum -action loggedon
net-enum -action loggedon -target FILESERVER
net-enum -action sessions
net-enum -action sessions -target DC01
net-enum -action shares
net-enum -action shares -target DC01
net-enum -action mapped
```

## MITRE ATT&CK Mapping

- **T1087.001** — Account Discovery: Local Account
- **T1087.002** — Account Discovery: Domain Account
- **T1069.001** — Permission Groups Discovery: Local Groups
- **T1069.002** — Permission Groups Discovery: Domain Groups
- **T1033** — System Owner/User Discovery (loggedon)
- **T1049** — System Network Connections Discovery (sessions)
- **T1135** — Network Share Discovery (shares)
