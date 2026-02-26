+++
title = "etw"
chapter = false
weight = 157
hidden = false
+++

## Summary

Enumerate, stop, or blind ETW (Event Tracing for Windows) trace sessions and providers. Use reconnaissance actions (`sessions`, `providers`) to assess active telemetry, then use evasion actions (`stop`, `blind`) to disable it before performing sensitive operations.

The `blind` action is the preferred evasion method — it disables a specific provider within a session without stopping the session itself, making detection harder.

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | sessions | Action: `sessions`, `providers`, `stop`, or `blind` |
| session_name | For stop/blind | — | Target trace session name |
| provider | For blind | — | Provider GUID or shorthand name to disable |

### Actions

- **sessions** — List all active ETW trace sessions with security relevance classification
- **providers** — Enumerate all registered ETW providers, highlighting security-relevant ones
- **stop** — Stop an entire ETW trace session (ControlTrace API). Disables all telemetry from that session.
- **blind** — Surgically disable a specific provider within a trace session (EnableTraceEx2 API). The session remains active but the targeted provider no longer generates events. Stealthier than `stop`.

### Provider Shorthands

For the `blind` action, you can use shorthand names instead of raw GUIDs:

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
| kernel-file | Microsoft-Windows-Kernel-File |
| kernel-network | Microsoft-Windows-Kernel-Network |
| kernel-registry | Microsoft-Windows-Kernel-Registry |
| api-calls | Microsoft-Windows-Kernel-Audit-API-Calls |
| task-scheduler | Microsoft-Windows-TaskScheduler |
| dns-client | Microsoft-Windows-DNS-Client |

## Usage

```
# Enumerate active ETW trace sessions
etw -action sessions

# List security-relevant ETW providers
etw -action providers

# Stop an entire trace session (nuclear option)
etw -action stop -session_name "EventLog-Security"

# Disable Sysmon provider in its session (surgical)
etw -action blind -session_name "EventLog-Microsoft-Windows-Sysmon/Operational" -provider sysmon

# Disable PowerShell logging provider
etw -action blind -session_name "EventLog-Microsoft-Windows-PowerShell/Operational" -provider powershell

# Disable AMSI provider using raw GUID
etw -action blind -session_name "EventLog-Security" -provider "F4E1897A-BB65-5399-F245-102D38640FFE"
```

## Operational Notes

- Run `etw -action sessions` first to identify active trace sessions and their security relevance
- **`blind` is preferred over `stop`** — it removes a single provider while the session continues to run, making detection harder
- **`stop` is the nuclear option** — it kills the entire session, which may be noticed by monitoring
- Requires Administrator or SYSTEM privileges for stop/blind actions
- Common high-value targets for blinding:
  - **Sysmon** — disable process/network/file monitoring
  - **PowerShell** — disable script block logging
  - **Kernel-Process** — disable process creation events
  - **AMSI** — disable script content inspection (also achievable via `autopatch`)
- Pair with `auditpol -action stealth` and `autopatch` for comprehensive telemetry evasion
- Note: stopping `EventLog-Security` prevents new Security events but generates no 1102 indicator (unlike `eventlog -action clear`)

## MITRE ATT&CK Mapping

- **T1082** — System Information Discovery (sessions/providers enumeration)
- **T1562.002** — Impair Defenses: Disable Windows Event Logging (stop action)
- **T1562.006** — Impair Defenses: Indicator Blocking (blind action)
