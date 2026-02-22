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

## Example Output

### List
```
Logon Sessions: 2

Session  User                   Domain             Station          State          Client
------------------------------------------------------------------------------------------------------
0        (none)                 -                  Services         Disconnected   -
2        setup                  Win1123H2          Console          Active         -

Summary: 2 sessions (1 with users) — 1 Disconnected, 1 Active
```

### Users
```
Unique Users: 1

User                           Sessions   Session Details
-----------------------------------------------------------------------
Win1123H2\setup                1          2(Active)
```

## MITRE ATT&CK Mapping

- T1033 — System Owner/User Discovery
