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

## Output Format

Returns JSON output, rendered by a browser script into sortable tables. The structure varies by action.

### List Actions (users, localgroups, domainusers, domaingroups, groupmembers)

Returns a JSON array of entries:
```json
[
  {"name": "Administrator", "type": "local_user", "comment": "Built-in account for administering the computer/domain", "source": ""},
  {"name": "Guest", "type": "local_user", "comment": "Built-in account for guest access", "source": ""}
]
```

### domaininfo Action

Returns a structured JSON object with DC information, account policy, and trust relationships:
```json
{
  "dc": {"name": "DC01", "address": "\\\\192.168.1.10", "domain": "CORP.LOCAL", "forest": "CORP.LOCAL", "site": "Default-First-Site-Name"},
  "policy": {"min_password_length": 7, "max_password_age_days": 42, "lockout_threshold": 0},
  "trusts": [{"name": "CHILD.CORP.LOCAL", "type": "Uplevel", "direction": "Bidirectional", "attributes": "WithinForest"}]
}
```

### Browser Script Rendering

The browser script renders results as sortable tables:
- **List actions**: Single sortable table with columns appropriate to the action (Name, Type, Comment, Source)
- **domaininfo**: Two-table layout showing DC info/policy in one table and trust relationships in a second table

## MITRE ATT&CK Mapping

- **T1087.001** — Account Discovery: Local Account
- **T1087.002** — Account Discovery: Domain Account
- **T1069.001** — Permission Groups Discovery: Local Groups
- **T1069.002** — Permission Groups Discovery: Domain Groups
