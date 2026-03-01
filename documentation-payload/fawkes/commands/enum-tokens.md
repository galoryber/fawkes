+++
title = "enum-tokens"
chapter = false
weight = 102
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Enumerate access tokens across all accessible processes on the system. Shows which users have active processes, their integrity levels, and session IDs. This is essential for planning lateral movement via `steal-token` — it answers "which process should I steal a token from?"

Auto-enables SeDebugPrivilege for maximum visibility into other users' processes. Processes that cannot be opened (e.g., kernel-protected) show as "(access denied)".

## Arguments

### action
- `list` (default) — Show all process tokens in a table: PID, process name, user, integrity level, session ID
- `unique` — Show unique token owners grouped with process counts, session list, and example process names

### user
Optional case-insensitive substring filter. Only show tokens matching this user string.

## Usage

List all process tokens:
```
enum-tokens
```

Show unique users with process counts:
```
enum-tokens -action unique
```

Filter to SYSTEM tokens only:
```
enum-tokens -action list -user SYSTEM
```

Filter to a specific user:
```
enum-tokens -action unique -user setup
```

### Browser Script

Output is rendered as a sortable table in the Mythic UI. Rows are color-coded by integrity level: System (red), High (orange), Low (gray).

## Example Output (JSON)

### List Action
```json
[
  {"pid":4,"process":"System","user":"NT AUTHORITY\\SYSTEM","integrity":"System","session":0},
  {"pid":672,"process":"svchost.exe","user":"NT AUTHORITY\\SYSTEM","integrity":"System","session":0}
]
```

### Unique Action
```json
[
  {"user":"NT AUTHORITY\\SYSTEM","integrity":"System","count":63,"sessions":[0,2],"processes":["System","csrss.exe"]},
  {"user":"Win1123H2\\setup","integrity":"High","count":42,"sessions":[0,2],"processes":["explorer.exe"]}
]
```

## MITRE ATT&CK Mapping

- T1134 — Access Token Manipulation (token enumeration for steal-token planning)
- T1057 — Process Discovery (cross-process enumeration)
