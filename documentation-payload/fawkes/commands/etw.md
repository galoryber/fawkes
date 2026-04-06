+++
title = "etw"
chapter = false
weight = 157
hidden = false
+++

## Summary

Audit/telemetry subsystem manipulation for defense evasion. Cross-platform:

- **Windows:** Enumerate, stop, or blind ETW trace sessions and providers
- **Linux:** Manage auditd rules, journald logs, syslog configuration, and detect SIEM agents
- **macOS:** Query unified logging categories, detect security agents, check audit status

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | sessions (Win), rules (Linux), categories (macOS) | Operation to perform (see platform sections) |
| session_name | Varies | — | Windows: ETW session name. Linux: audit rule spec for disable-rule |
| provider | Varies | — | Windows: provider GUID/shorthand. Linux: vacuum duration for journal-clear. macOS: subsystem filter |

## Windows Actions

| Action | Description |
|--------|-------------|
| sessions | List active ETW trace sessions with security relevance |
| providers | Enumerate registered ETW providers |
| stop | Stop an entire trace session (ControlTrace API) |
| blind | Disable a specific provider within a session (EnableTraceEx2) |
| query | Get detailed session information |
| enable | Re-enable a previously blinded provider |

### Provider Shorthands

| Shorthand | Provider |
|-----------|----------|
| sysmon | Microsoft-Windows-Sysmon |
| amsi | Microsoft-Antimalware-Scan-Interface |
| powershell | Microsoft-Windows-PowerShell |
| dotnet | Microsoft-Windows-DotNETRuntime |
| winrm | Microsoft-Windows-WinRM |
| wmi | Microsoft-Windows-WMI-Activity |
| security-auditing | Microsoft-Windows-Security-Auditing |
| kernel-process | Microsoft-Windows-Kernel-Process |

## Linux Actions

| Action | Description |
|--------|-------------|
| rules | Enumerate active auditd rules (auditctl -l or config files) |
| disable-rule | Remove a specific auditd rule (session_name = rule spec) |
| journal-clear | Rotate and vacuum journald logs (provider = duration, default 1s) |
| journal-rotate | Rotate journal files without clearing |
| syslog-config | Enumerate rsyslog/syslog-ng configuration and forwarding targets |
| agents | Detect installed SIEM/security agents (14 vendors) |
| audit-status | Show audit subsystem status (auditctl -s or /proc) |

### Detected SIEM Agents (Linux)

Wazuh, osquery, Elastic (filebeat/auditbeat/packetbeat), CrowdStrike Falcon, SentinelOne, Carbon Black, Qualys, Rapid7, Tanium, Lacework, Sysdig Falco, Auditd, Suricata, Snort.

## macOS Actions

| Action | Description |
|--------|-------------|
| categories | Query unified logging for security-relevant entries (provider = subsystem filter) |
| agents | Detect installed security agents (17 products) |
| audit-status | Show OpenBSM audit config and SIP status |

### Detected Security Agents (macOS)

CrowdStrike, SentinelOne, Carbon Black, Jamf Protect/Connect, osquery, Elastic, Sophos, ESET, Kaspersky, Norton, Malwarebytes, Little Snitch, Lulu, BlockBlock, Oversight, Santa.

## Usage

```
# === Windows ===
etw -action sessions
etw -action stop -session_name "EventLog-Security"
etw -action blind -session_name "EventLog-Microsoft-Windows-Sysmon/Operational" -provider sysmon
etw -action enable -session_name "EventLog-Microsoft-Windows-Sysmon/Operational" -provider sysmon

# === Linux ===
# Enumerate audit rules
etw -action rules

# Check audit subsystem status
etw -action audit-status

# Disable a specific auditd rule
etw -action disable-rule -session_name "-w /etc/passwd -p wa"

# Clear journal logs (vacuum everything older than 1 second)
etw -action journal-clear

# Clear journal logs older than 1 hour
etw -action journal-clear -provider 1h

# Check syslog configuration
etw -action syslog-config

# Detect SIEM agents
etw -action agents

# === macOS ===
etw -action categories
etw -action categories -provider com.apple.securityd
etw -action agents
etw -action audit-status
```

## Operational Notes

- **Windows:** `blind` is preferred over `stop` — removes a single provider while session continues. Requires admin/SYSTEM.
- **Linux:** `disable-rule` and `journal-clear` require root privileges. Agent detection runs unprivileged.
- **macOS:** Most actions require root or appropriate TCC permissions. Agent detection via `ps` works unprivileged.
- Use `agents` action before operations to understand defensive coverage
- Pair with `autopatch` (AMSI/ETW patching) and `auditpol` (Windows) for comprehensive evasion

## MITRE ATT&CK Mapping

- **T1082** — System Information Discovery (enumeration actions)
- **T1562.001** — Disable or Modify Tools (disable-rule, agent detection)
- **T1562.002** — Disable Windows Event Logging (stop action)
- **T1562.006** — Indicator Blocking (blind action)
- **T1070.002** — Clear Linux/Mac System Logs (journal-clear)
