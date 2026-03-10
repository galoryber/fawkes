+++
title = "firewall"
chapter = false
weight = 108
hidden = false
+++

## Summary

Manage firewall rules and check firewall status. Windows uses `HNetCfg.FwPolicy2` COM API (no subprocess spawning). macOS queries Application Layer Firewall (ALF) and Packet Filter (pf). Linux auto-detects nftables or iptables and supports listing, adding, and deleting rules.

{{% notice info %}}Windows, macOS, and Linux{{% /notice %}}

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

## macOS Support

On macOS, `firewall` supports all 6 actions via the Application Layer Firewall (ALF) and Packet Filter (pf):

- **status**: Shows ALF state (enabled/stealth/block-all) and pf status
- **list**: Shows ALF application rules and pf filter/NAT rules
- **add**: Adds an application to the ALF (`-program` required, `-rule_action allow|block`)
- **delete**: Removes an application from the ALF (`-program` required)
- **enable**: Enables the Application Firewall globally
- **disable**: Disables the Application Firewall globally

### macOS Examples
```
firewall -action status
firewall -action add -program /usr/local/bin/myapp -rule_action block
firewall -action delete -program /usr/local/bin/myapp
firewall -action disable
```

Root access is required for enable/disable/add/delete and full pf rule listing. ALF status is available at any privilege level.

## Operational Notes

### Windows
- **COM API**: Uses `HNetCfg.FwPolicy2` and `HNetCfg.FWRule` COM objects — no subprocess spawning, no netsh.exe
- **Privileges**: Listing rules and checking status work at any privilege level. Adding, deleting, enabling, or disabling rules requires administrator privileges.
- **All profiles**: New rules are created for all profiles (Domain + Private + Public) by default
- **Rule names**: Multiple rules can share the same name in Windows Firewall. Delete removes by name match.
- **Opsec**: Use legitimate-sounding rule names (e.g., "Windows Update Service", "BITS Transfer") to blend in with existing rules

### macOS
- Uses `socketfilterfw` for ALF management and `pfctl` for pf rule queries
- The `add`/`delete` actions operate on the Application Layer Firewall (application-level allow/block), not pf rules
- The `-name` parameter is not used on macOS — use `-program` with the application path instead

### Linux
- **Auto-detection**: Prefers nftables (`nft`) if available, falls back to iptables
- **status**: Shows chain policies and rule counts. Detects UFW if present.
- **list**: Lists all rules from all tables (filter/nat/mangle/raw). Supports `-filter` substring matching.
- **add**: Adds a rule to INPUT or OUTPUT chain. `-name` sets a comment for later identification. `-protocol` and `-port` supported. `-rule_action` maps to ACCEPT/DROP.
- **delete**: Mirrors the add rule spec with `-D` (iptables) or searches by comment handle (nftables)
- **enable/disable**: Not supported — Linux has no global firewall toggle. Returns informative guidance.
- Root access generally required for all operations
- Note: The separate `iptables` command also exists for lower-level iptables/nftables management

### Linux Examples
```
firewall -action status
firewall -action list
firewall -action list -filter "ssh"
firewall -action add -name "Allow HTTPS" -direction in -protocol tcp -port 443 -rule_action allow
firewall -action delete -name "Allow HTTPS" -direction in -protocol tcp -port 443 -rule_action allow
```

## MITRE ATT&CK Mapping

- **T1562.004** — Impair Defenses: Disable or Modify System Firewall
