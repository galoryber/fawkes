+++
title = "logonsessions"
chapter = false
weight = 105
hidden = false
+++

## Summary

Enumerate active logon sessions on the system. Shows which users are logged in, their session IDs, connection state, and terminal station.

Two actions are available:
- **list** (default): Show all sessions including system sessions
- **users**: Show only unique logged-on users with their session details

Optional username filter to narrow results.

### Platform Details

- **Windows**: Uses `WTSEnumerateSessionsW` + `WTSQuerySessionInformationW` — no subprocess creation.
- **Linux**: Natively parses `/var/run/utmp` binary (384-byte utmp records) — no subprocess creation. Shows active USER_PROCESS entries with PID, terminal, login time, and remote host.

### Arguments

#### action
Action to perform. Options: `list` (default), `users`.

#### filter
Optional: filter results by username substring (case-insensitive). On Windows, also matches domain.

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

### JSON Structure (Windows)
```json
[
  {"session_id": 0, "username": "(none)", "domain": "-", "station": "Services", "state": "Disconnected", "client": ""},
  {"session_id": 2, "username": "setup", "domain": "Win1123H2", "station": "Console", "state": "Active", "client": ""}
]
```

### JSON Structure (Linux)
```json
[
  {"session_id": 42, "username": "gary", "domain": "", "station": "pts/0", "state": "Active", "client": "192.168.1.100", "pid": 1234, "login_time": "2026-03-09 16:00:00"},
  {"session_id": 43, "username": "root", "domain": "", "station": "tty1", "state": "Active", "pid": 567, "login_time": "2026-03-09 12:00:00"}
]
```

### Browser Script Rendering

The browser script renders results as a color-coded sortable table:
- **Green** rows indicate **Active** sessions
- **Orange** rows indicate **Disconnected** sessions

Columns: Session ID, Username, Domain, Station, State, Client.

## MITRE ATT&CK Mapping

- T1033 — System Owner/User Discovery
