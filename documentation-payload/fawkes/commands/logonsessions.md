+++
title = "logonsessions"
chapter = false
weight = 105
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Enumerate active logon sessions on the system using the Windows Terminal Services (WTS) API. Shows which users are logged in, their session IDs, connection state, and terminal station.

Two actions are available:
- **list** (default): Show all sessions including system sessions
- **users**: Show only unique logged-on users with their session details

Optional username/domain filter to narrow results.

Uses `WTSEnumerateSessionsW` + `WTSQuerySessionInformationW` — no subprocess creation.

### Arguments

#### action
Action to perform. Options: `list` (default), `users`.

#### filter
Optional: filter results by username or domain substring (case-insensitive).

## Usage

List all sessions:
```
logonsessions
```

Show unique users only:
```
logonsessions -action users
```

Filter by username:
```
logonsessions -action list -filter setup
```

## Output Format

Returns JSON array of session entries, rendered by a browser script into a sortable table.

### JSON Structure
```json
[
  {"session_id": 0, "username": "(none)", "domain": "-", "station": "Services", "state": "Disconnected", "client": ""},
  {"session_id": 2, "username": "setup", "domain": "Win1123H2", "station": "Console", "state": "Active", "client": ""}
]
```

### Browser Script Rendering

The browser script renders results as a color-coded sortable table:
- **Green** rows indicate **Active** sessions
- **Orange** rows indicate **Disconnected** sessions

Columns: Session ID, Username, Domain, Station, State, Client.

## MITRE ATT&CK Mapping

- T1033 — System Owner/User Discovery
