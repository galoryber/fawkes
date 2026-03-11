+++
title = "eventlog"
chapter = false
weight = 106
hidden = false
+++

{{% notice info %}}
Windows and Linux
{{% /notice %}}

## Summary

Manage system event logs across platforms. **Windows**: Uses the modern Event Log API (`wevtapi.dll`) to list channels, query events, clear logs, and enable/disable channels. **Linux**: Queries journald (systemd journal) for structured log entries and reads syslog files directly.

### Actions

- **list** — Enumerate available log sources (Windows: channels, Linux: journal units + /var/log files)
- **query** — Query events with filtering (Windows: XPath/EventID, Linux: keyword/priority/time window)
- **clear** — Clear logs (Windows: EvtClearLog, Linux: journal vacuum or file truncation)
- **info** — Display metadata: record count, file size, disk usage
- **enable** — Enable an event log channel (Windows only; Linux returns guidance)
- **disable** — Disable an event log channel (Windows only; Linux returns guidance)

### Requirements

**Windows:**
- **List/Query**: No special privileges for most channels; Security log requires Administrator
- **Clear**: Administrator privileges; `SeSecurityPrivilege` enabled automatically
- **SYSTEM recommended**: Run `getsystem` first for maximum access

**Linux:**
- **List/Query**: No special privileges for most logs; some files may require root
- **Clear**: Root privileges required for journal vacuum and log file truncation
- Journald queries require `journalctl` (systemd systems); non-systemd falls back to file-based access

### Arguments

#### action
The operation to perform. Default: `list`.
- `list` — List available log sources
- `query` — Query events from a specific source
- `clear` — Clear/vacuum logs
- `info` — Get log metadata
- `enable` — Enable event log channel (Windows only)
- `disable` — Disable event log channel (Windows only)

#### channel
**Windows:** Event log channel name (e.g., `Security`, `System`, `Microsoft-Windows-PowerShell/Operational`).
**Linux:** Systemd unit name (e.g., `sshd.service`) or file path (e.g., `/var/log/auth.log`). When a file path is specified, reads the file directly (no subprocess creation — opsec friendly).

#### event_id
**Windows:** Filter by specific Event ID (e.g., `4624` for logon events).
**Linux:** Filter by syslog priority (0=emerg through 7=debug, lower is more severe).

#### filter
Filter string:
- For `list`: substring match on channel/unit names
- For `query`:
  - **Time window** — `24h`, `7d`, `30m` (both platforms)
  - **XPath** — Raw XPath expression (Windows only)
  - **Keyword** — grep-style keyword search (Linux only)

#### count
Maximum number of events to return. Default: `50`.

## Usage

### Windows Examples

List channels matching "Security":
```
eventlog -action list -filter Security
```

Query logon events (EventID 4624):
```
eventlog -action query -channel Security -event_id 4624 -count 5
```

Query System events from the last 24 hours:
```
eventlog -action query -channel System -filter 24h
```

Clear the Security log:
```
eventlog -action clear -channel Security
```

Disable Sysmon event collection:
```
eventlog -action disable -channel Microsoft-Windows-Sysmon/Operational
```

### Linux Examples

List all journal units and log files:
```
eventlog
```

List units matching "ssh":
```
eventlog -action list -filter ssh
```

Query SSH journal entries:
```
eventlog -action query -channel sshd.service -count 20
```

Query auth.log directly (no subprocess — opsec friendly):
```
eventlog -action query -channel /var/log/auth.log -filter "Failed password" -count 50
```

Query high-priority journal entries from the last 24 hours:
```
eventlog -action query -filter 24h -event_id 3
```

Get journal disk usage and metadata:
```
eventlog -action info
```

Get info about a specific log file:
```
eventlog -action info -channel /var/log/syslog
```

Vacuum journal entries (clear all):
```
eventlog -action clear
```

Truncate a specific log file:
```
eventlog -action clear -channel /var/log/auth.log
```

## Example Output

### Windows — Query Events
```
Events from 'Security' (max 5, newest first):

[1] 2026-02-23T15:21:23 | EventID: 4672 | Info | Microsoft-Windows-Security-Auditing
[2] 2026-02-23T15:21:23 | EventID: 4624 | Info | Microsoft-Windows-Security-Auditing
[3] 2026-02-23T15:21:23 | EventID: 4648 | Info | Microsoft-Windows-Security-Auditing

Total: 3 events returned
```

### Linux — List Sources
```
Journal Boots:
   0 abc123 2026-03-10 08:00:00 CDT—2026-03-11 08:00:00 CDT

Journal Units (42):
  sshd.service
  systemd-journald.service
  cron.service
  ...

Disk Usage: Archived and active journals take up 128.0M in the file system.

Log Files in /var/log/:
  auth.log                          52480 bytes  2026-03-11 07:55:00
  syslog                           128000 bytes  2026-03-11 08:00:00
  kern.log                          12800 bytes  2026-03-10 22:00:00
```

### Linux — Query Journal
```
Journal entries (max 20, newest first):
Unit: sshd.service

2026-03-11T08:00:00-0500 host sshd[1234]: Accepted publickey for user from 10.0.0.1 port 22
2026-03-11T07:55:00-0500 host sshd[1230]: Failed password for root from 10.0.0.2 port 22
```

## Key Security Event IDs (Windows)

| Event ID | Description |
|----------|-------------|
| 1102 | Audit log cleared (auto-generated on clear) |
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4648 | Logon using explicit credentials |
| 4672 | Special privileges assigned to new logon |
| 4688 | New process created |
| 4689 | Process terminated |
| 4720 | User account created |
| 4732 | Member added to security-enabled local group |
| 7045 | New service installed |

## Syslog Priorities (Linux)

| Priority | Level | Description |
|----------|-------|-------------|
| 0 | emerg | System is unusable |
| 1 | alert | Action must be taken immediately |
| 2 | crit | Critical conditions |
| 3 | err | Error conditions |
| 4 | warning | Warning conditions |
| 5 | notice | Normal but significant |
| 6 | info | Informational messages |
| 7 | debug | Debug-level messages |

## MITRE ATT&CK Mapping

- T1070.001 — Indicator Removal: Clear Windows Event Logs
- T1562.002 — Impair Defenses: Disable Windows Event Logging (disable action)
