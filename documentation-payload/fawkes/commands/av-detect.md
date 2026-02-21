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

### Example Output (Windows)
```
Security Products Detected: 2 unique product(s)

Product                             Vendor          Type       Process                   PID
----------------------------------------------------------------------------------------------------
Windows Defender                    Microsoft       AV         MsMpEng.exe               3400
Windows Security Health             Microsoft       AV         SecurityHealthSystray.exe  6440

Summary: 2 AV
```

### Example Output (macOS)
```
Security Products Detected: 2 unique product(s)

Product                             Vendor          Type       Process                   PID
----------------------------------------------------------------------------------------------------
Endpoint Security                   Apple           EDR        endpointsecurityd         346
XProtect                            Apple           AV         XprotectService           697

Summary: 1 EDR, 1 AV
```

## Supported Products

Categories: AV, EDR, Firewall, Logging

Major vendors covered: Microsoft Defender/MDE, CrowdStrike Falcon, SentinelOne, Carbon Black, Cortex XDR, Symantec/Broadcom, McAfee/Trellix, Kaspersky, ESET, Sophos, Trend Micro, Bitdefender, Cylance, Elastic, Cisco AMP, Cybereason, Fortinet, WatchGuard, Tanium, Rapid7, Sysmon, Splunk, Wazuh, OSSEC, Qualys, Apple XProtect, ClamAV, Linux Audit.

## MITRE ATT&CK Mapping

- **T1518.001** - Software Discovery: Security Software Discovery
