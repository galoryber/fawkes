+++
title = "sysmon-config"
chapter = false
weight = 192
hidden = false
+++

## Summary

Detects Sysmon installation and extracts its active configuration from the Windows registry. Identifies standard and renamed Sysmon installations by checking service registry keys and minifilter driver altitude (385201).

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | check | Action: `check` (detect + config summary), `rules` (dump raw rule hex), `events` (list event types and status) |

## Usage

Detect Sysmon and show configuration summary:
```
sysmon-config
```

Dump raw Sysmon rules (hex):
```
sysmon-config -action rules
```

List all Sysmon event types with active/inactive status:
```
sysmon-config -action events
```

### What It Checks

| Item | Source |
|------|--------|
| Service presence | `HKLM\SYSTEM\CurrentControlSet\Services\Sysmon64` (and `Sysmon`) |
| Driver presence | `HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters` |
| Renamed installs | Minifilter instance altitude 385201 scan |
| Hash algorithm | `HashingAlgorithm` registry value |
| Options flags | `Options` bitmask (network, image load, crypto, clipboard logging) |
| Rule config | `Rules` binary blob size |
| Event channels | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\*Sysmon*` |

## MITRE ATT&CK Mapping

- **T1518.001** — Software Discovery: Security Software Discovery
- **T1562.001** — Impair Defenses: Disable or Modify Tools
