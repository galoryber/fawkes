+++
title = "defender"
chapter = false
weight = 109
hidden = false
+++

## Summary

Query Windows Defender status, manage exclusions, and view threat history. Uses WMI (`root\Microsoft\Windows\Defender` namespace) for detailed status and threat queries, with registry fallback for reliability. Exclusion management reads from and writes to the Defender registry keys directly.

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | status | Action: `status`, `exclusions`, `add-exclusion`, `remove-exclusion`, `threats` |
| type | For add/remove-exclusion | path | Exclusion type: `path`, `process`, `extension` |
| value | For add/remove-exclusion | - | Exclusion value (path, process name, or extension) |

## Usage

### Check Defender Status
```
defender -action status
```
Shows Defender service state, real-time protection, antivirus/antispyware status, scan ages, and registry-based policy settings. Tries WMI first for detailed info, falls back to registry if WMI is unavailable.

### List Exclusions
```
defender -action exclusions
```
Shows all configured Defender exclusions (paths, processes, extensions) from both the standard Defender registry keys and Group Policy-managed exclusion keys.

### Add an Exclusion
```
defender -action add-exclusion -type path -value "C:\Tools"
defender -action add-exclusion -type process -value "payload.exe"
defender -action add-exclusion -type extension -value ".ps1"
```
Requires administrator privileges.

### Remove an Exclusion
```
defender -action remove-exclusion -type path -value "C:\Tools"
```
Requires administrator privileges.

### View Threat History
```
defender -action threats
```
Shows recent threat detections from the MSFT_MpThreatDetection WMI class.

## Example Output

### Status
```
Windows Defender Status:

AMRunningMode=Normal
AMServiceEnabled=true
AntispywareEnabled=true
AntivirusEnabled=true
BehaviorMonitorEnabled=true
RealTimeProtectionEnabled=true
QuickScanAge=0
FullScanAge=-1

--- Registry Details ---
Windows Defender Status (from registry):

  DisableAntiSpyware: 0
```

### Exclusions
```
Windows Defender Exclusions:

  Path Exclusions:
    - C:\Users\setup\Downloads
  Process Exclusions:
    (none)
  Extension Exclusions:
    (none)

  Policy-Based Exclusions:

  Total: 1 exclusions
```

### Add Exclusion
```
Added Defender path exclusion: C:\Tools
```

## Operational Notes

- **WMI + Registry**: Status uses WMI (`MSFT_MpComputerStatus`) with a 15-second timeout, falling back to registry if WMI is unavailable or slow
- **Registry-based exclusions**: Reads from `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\{Paths,Processes,Extensions}` and policy keys under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\`
- **Privileges**: Reading status and exclusions works at any privilege level. Adding or removing exclusions requires administrator privileges (registry SET_VALUE access).
- **Tamper Protection**: If Defender Tamper Protection is enabled, registry-based exclusion changes may be blocked even with admin privileges. Use PowerShell `Set-MpPreference` or Group Policy instead.
- **Opsec**: Exclusion reads are passive registry reads. Exclusion writes modify Defender registry keys, which may be logged by EDR.

## MITRE ATT&CK Mapping

- **T1562.001** — Impair Defenses: Disable or Modify Tools
