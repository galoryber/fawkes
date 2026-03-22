+++
title = "av-detect"
chapter = false
weight = 10
hidden = false
+++

## Summary

Detect installed AV, EDR, and security products by scanning running processes against a built-in signature database of 130+ known security product process names. Reports product name, vendor, category, process name, and PID.

With `--deep` mode (Linux), extends detection beyond running processes to check kernel modules, systemd service units, and known config directories. This catches products that are installed but not currently running as a visible process.

This is useful for operators to quickly assess the security posture of a target before deciding on evasion techniques, injection methods, or persistence mechanisms.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| deep | No | false | Enable deep scanning: check kernel modules, systemd units, and config directories (Linux only) |

## Usage
```
av-detect
av-detect -deep true
```

### Output Format

Returns a JSON array of detected security products (rendered as a sortable table in the Mythic UI with color-coded categories):

```json
[
  {"product": "Windows Defender", "vendor": "Microsoft", "category": "AV", "process": "MsMpEng.exe", "pid": 3400},
  {"product": "Defender for Endpoint", "vendor": "Microsoft", "category": "EDR", "process": "MsSense.exe", "pid": 1520}
]
```

Deep scan results use PID 0 and a prefixed process name indicating the detection source:
```json
[
  {"product": "CrowdStrike Falcon", "vendor": "CrowdStrike", "category": "EDR", "process": "kmod:falcon_lsm_serviceable", "pid": 0},
  {"product": "Elastic Agent", "vendor": "Elastic", "category": "EDR", "process": "systemd:elastic-agent.service", "pid": 0},
  {"product": "Splunk Forwarder", "vendor": "Splunk", "category": "Logging", "process": "config:/opt/SplunkForwarder", "pid": 0}
]
```

Returns `[]` when no security products are detected.

## Deep Scan Sources (Linux)

- **Kernel modules**: Checks `/proc/modules` for known security kernel modules (CrowdStrike, SentinelOne, Carbon Black, Sophos, etc.)
- **Systemd units**: Checks `/etc/systemd/system/`, `/lib/systemd/system/`, `/usr/lib/systemd/system/` for known service files
- **Config directories**: Checks known installation paths (`/opt/CrowdStrike`, `/opt/sentinelone`, `/opt/microsoft/mdatp`, etc.)

Results are deduplicated — a product found via multiple sources is reported only once.

## Supported Products

Categories: AV, EDR, Firewall, Logging

Major vendors covered: Microsoft Defender/MDE, CrowdStrike Falcon, SentinelOne, Carbon Black, Cortex XDR, Symantec/Broadcom, McAfee/Trellix, Kaspersky, ESET, Sophos, Trend Micro, Bitdefender, Cylance, Elastic, Cisco AMP, Cybereason, Fortinet, WatchGuard, Tanium, Rapid7, Sysmon, Splunk, Wazuh, OSSEC, Qualys, Apple XProtect, ClamAV, Linux Audit, osquery, Filebeat.

## MITRE ATT&CK Mapping

- **T1518.001** - Software Discovery: Security Software Discovery
