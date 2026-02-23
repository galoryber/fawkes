+++
title = "eventlog"
chapter = false
weight = 106
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Manage Windows Event Logs using the modern Windows Event Log API (`wevtapi.dll`). Supports listing available log channels, querying events with XPath filtering, clearing logs, and getting channel information.

### Actions

- **list** — Enumerate available event log channels with optional name filter
- **query** — Query events from a specific channel with XPath, EventID, or time filtering
- **clear** — Clear all events from a specific log channel (generates Event ID 1102)
- **info** — Display channel metadata: record count, file size, last write time

### Requirements

- **List/Query**: No special privileges needed for most channels; Security log requires Administrator or Event Log Readers group
- **Clear**: Administrator privileges required; `SeSecurityPrivilege` enabled automatically for Security log
- **SYSTEM recommended**: Run `getsystem` first for maximum access

### Arguments

#### action
The operation to perform. Default: `list`.
- `list` — List available event log channels
- `query` — Query events from a channel
- `clear` — Clear a log channel
- `info` — Get channel information

#### channel
Event log channel name. Required for `query`, `clear`, and `info` actions.
Common channels: `Security`, `System`, `Application`, `Microsoft-Windows-PowerShell/Operational`.

#### event_id
Filter by specific Event ID (for `query` action). Example: `4624` for logon events.

#### filter
Filter string:
- For `list`: substring match on channel names
- For `query`: time window (e.g., `24h`, `1h`) or raw XPath expression

#### count
Maximum number of events to return. Default: `50`.

## Usage

List all channels:
```
eventlog
```

List channels matching "Security":
```
eventlog -action list -filter Security
```

Get info about the Security log:
```
eventlog -action info -channel Security
```

Query the last 10 Security events:
```
eventlog -action query -channel Security -count 10
```

Query logon events (EventID 4624):
```
eventlog -action query -channel Security -event_id 4624 -count 5
```

Query System events from the last 24 hours:
```
eventlog -action query -channel System -filter 24h
```

Query with raw XPath:
```
eventlog -action query -channel Security -filter "*[System[EventID=4625]]"
```

Clear the Security log:
```
eventlog -action clear -channel Security
```

## Example Output

### List Channels
```
Event Log Channels (32, filter: 'Security'):

  Security
  Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
  Microsoft-Windows-Windows Firewall With Advanced Security/FirewallVerbose
  ...
```

### Query Events
```
Events from 'Security' (max 5, newest first):

[1] 2026-02-23T15:21:23 | EventID: 4672 | Info | Microsoft-Windows-Security-Auditing
[2] 2026-02-23T15:21:23 | EventID: 4624 | Info | Microsoft-Windows-Security-Auditing
[3] 2026-02-23T15:21:23 | EventID: 4648 | Info | Microsoft-Windows-Security-Auditing
[4] 2026-02-23T15:21:23 | EventID: 4798 | Info | Microsoft-Windows-Security-Auditing
[5] 2026-02-23T15:21:23 | EventID: 4634 | Info | Microsoft-Windows-Security-Auditing

Total: 5 events returned
```

### Channel Info
```
Event Log Info: Application

  Records:     61780
  File Size:   20.0 MB
  Last Write:  2026-02-23 15:10:00 UTC
```

## Key Security Event IDs

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

## MITRE ATT&CK Mapping

- T1070.001 — Indicator Removal: Clear Windows Event Logs
