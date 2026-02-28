+++
title = "av-detect"
chapter = false
weight = 10
hidden = false
+++

## Summary

Detect installed AV, EDR, and security products by scanning running processes against a built-in signature database of 130+ known security product process names. Reports product name, vendor, category, process name, and PID.

This is useful for operators to quickly assess the security posture of a target before deciding on evasion techniques, injection methods, or persistence mechanisms.

## Arguments

None — the command takes no parameters.

## Usage
```
av-detect
```

### Output Format

Returns a JSON array of detected security products (rendered as a sortable table in the Mythic UI with color-coded categories):

```json
[
  {"product": "Windows Defender", "vendor": "Microsoft", "category": "AV", "process": "MsMpEng.exe", "pid": 3400},
  {"product": "Defender for Endpoint", "vendor": "Microsoft", "category": "EDR", "process": "MsSense.exe", "pid": 1520}
]
```

Returns `[]` when no security products are detected.

## Supported Products

Categories: AV, EDR, Firewall, Logging

Major vendors covered: Microsoft Defender/MDE, CrowdStrike Falcon, SentinelOne, Carbon Black, Cortex XDR, Symantec/Broadcom, McAfee/Trellix, Kaspersky, ESET, Sophos, Trend Micro, Bitdefender, Cylance, Elastic, Cisco AMP, Cybereason, Fortinet, WatchGuard, Tanium, Rapid7, Sysmon, Splunk, Wazuh, OSSEC, Qualys, Apple XProtect, ClamAV, Linux Audit.

## MITRE ATT&CK Mapping

- **T1518.001** - Software Discovery: Security Software Discovery
