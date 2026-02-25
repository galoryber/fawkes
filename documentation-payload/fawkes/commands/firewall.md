+++
title = "firewall"
chapter = false
weight = 108
hidden = false
+++

## Summary

Manage Windows Firewall rules via the `HNetCfg.FwPolicy2` COM API. Supports listing, creating, deleting, enabling, disabling rules, and checking firewall profile status. No subprocess spawning (netsh.exe is never called).

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | list | Action: `list`, `add`, `delete`, `enable`, `disable`, `status` |
| name | For add/delete/enable/disable | - | Rule name |
| direction | No | in | Rule direction: `in` (inbound) or `out` (outbound) |
| rule_action | No | allow | Rule action: `allow` or `block` |
| protocol | No | any | Protocol: `tcp`, `udp`, or `any` |
| port | No | - | Port number or range (e.g., `443`, `8080-8090`) |
| program | No | - | Program path to associate with rule |
| filter | No | - | Filter rules by name substring (for list) |
| enabled | No | - | Filter by enabled state: `true` or `false` (for list) |

## Usage

### Check Firewall Status
```
firewall -action status
```
Shows enabled/disabled state for each profile (Domain, Private, Public), default inbound/outbound actions, active profile, and total rule count.

### List All Rules
```
firewall -action list
```
Shows all firewall rules with name, direction, action, protocol, enabled state, ports, and program path.

### List Rules with Filter
```
firewall -action list -filter "Remote Desktop"
firewall -action list -direction in -enabled true
```

### Add a Firewall Rule
```
firewall -action add -name "Windows Update Service" -direction in -rule_action allow -protocol tcp -port 443
firewall -action add -name "Custom App" -protocol tcp -port 8080 -program "C:\Program Files\App\app.exe"
```

### Delete a Rule
```
firewall -action delete -name "Windows Update Service"
```

### Enable/Disable a Rule
```
firewall -action disable -name "Remote Desktop - User Mode (TCP-In)"
firewall -action enable -name "Remote Desktop - User Mode (TCP-In)"
```

## Example Output

### Status
```
Windows Firewall Status:

  Domain:    Enabled=true   DefaultInbound=Block   DefaultOutbound=Allow
  Private:   Enabled=true   DefaultInbound=Block   DefaultOutbound=Allow
  Public:    Enabled=true   DefaultInbound=Block   DefaultOutbound=Allow [ACTIVE]

  Total Rules: 548
```

### List (Filtered)
```
Windows Firewall Rules:

Name                                          Dir   Action   Proto  Enabled  LocalPorts      Program
------------------------------------------------------------------------------------------------------------------------
FawkesTestRule_12345                          In    Allow    TCP    true     9999

Showing 1/549 rules
```

### Add Rule
```
Firewall rule added:
  Name:      Windows Update Service
  Direction: In
  Action:    Allow
  Protocol:  TCP
  Port:      443
  Enabled:   true
  Profiles:  All
```

## Operational Notes

- **COM API**: Uses `HNetCfg.FwPolicy2` and `HNetCfg.FWRule` COM objects — no subprocess spawning, no netsh.exe
- **Privileges**: Listing rules and checking status work at any privilege level. Adding, deleting, enabling, or disabling rules requires administrator privileges.
- **All profiles**: New rules are created for all profiles (Domain + Private + Public) by default
- **Rule names**: Multiple rules can share the same name in Windows Firewall. Delete removes by name match.
- **Opsec**: Use legitimate-sounding rule names (e.g., "Windows Update Service", "BITS Transfer") to blend in with existing rules

## MITRE ATT&CK Mapping

- **T1562.004** — Impair Defenses: Disable or Modify System Firewall
