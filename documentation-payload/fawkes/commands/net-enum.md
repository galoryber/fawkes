+++
title = "net-enum"
chapter = false
weight = 47
hidden = false
+++

## Summary

Enumerate local and domain users, groups, and domain configuration using direct Win32 API calls (NetUserEnum, NetLocalGroupEnum, NetGroupEnum, DsGetDcNameW, DsEnumerateDomainTrustsW). No subprocess creation — all operations run in-process via netapi32.dll. Essential for situational awareness during red team engagements.

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | Yes | Enumeration action: `users`, `localgroups`, `groupmembers`, `domainusers`, `domaingroups`, `domaininfo` |
| target | Conditional | Group name for `groupmembers` action |

## Usage

### List local users
```
net-enum -action users
```

### List local groups
```
net-enum -action localgroups
```

### List members of a specific group
```
net-enum -action groupmembers -target Administrators
net-enum -action groupmembers -target "Remote Desktop Users"
```

### List domain users
```
net-enum -action domainusers
```

### List domain groups
```
net-enum -action domaingroups
```

### Get domain information (account policy, DCs, trusts)
```
net-enum -action domaininfo
```

## MITRE ATT&CK Mapping

- **T1087.001** — Account Discovery: Local Account
- **T1087.002** — Account Discovery: Domain Account
- **T1069.001** — Permission Groups Discovery: Local Groups
- **T1069.002** — Permission Groups Discovery: Domain Groups
