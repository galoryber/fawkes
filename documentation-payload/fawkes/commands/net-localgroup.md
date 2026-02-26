+++
title = "net-localgroup"
chapter = false
weight = 159
hidden = false
+++

## Summary

Enumerate local groups and their members on local or remote Windows machines via the NetLocalGroup Win32 APIs. Includes an `admins` shortcut for quickly identifying local administrator accounts — essential for lateral movement planning.

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | list | Action: `list` (all groups), `members` (group membership), `admins` (Administrators shortcut) |
| group | For members | — | Group name to enumerate (e.g., "Administrators", "Remote Desktop Users") |
| server | No | localhost | Remote server hostname or IP to query. UNC prefix added automatically. |

## Usage

```
# List all local groups on current machine
net-localgroup

# Find local administrators (shortcut)
net-localgroup -action admins

# Enumerate members of a specific group
net-localgroup -action members -group "Remote Desktop Users"

# Query local admins on a remote host
net-localgroup -action admins -server 192.168.100.51

# List groups on a remote host
net-localgroup -action list -server DC01
```

## Output

- **list**: Shows all local groups with their descriptions
- **members/admins**: Shows each member with their SID type (User, Group, WellKnownGroup, Computer, Alias)

## Operational Notes

- Remote queries require appropriate network-level authentication (current token or impersonated identity)
- Use with `net-enum -action users` for full local account enumeration
- The `admins` action is equivalent to `members -group Administrators` but faster to type during an engagement
- Combine with `steal-token` or `make-token` to query remote hosts with stolen credentials

## MITRE ATT&CK Mapping

- **T1069.001** — Permission Groups Discovery: Local Groups
