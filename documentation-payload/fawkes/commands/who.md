+++
title = "who"
chapter = false
weight = 209
hidden = false
+++

## Summary

Show currently logged-in users and active sessions. Complementary to `last` (which shows historical login entries) — `who` shows only current active sessions.

Useful for understanding who is currently using the system, identifying active administrators, and determining if the system is actively monitored.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| all | No | false | Show all sessions including system accounts and non-user process entries |

## Usage

Show active user sessions:
```
who
```

Show all sessions including system:
```
who -all true
```

## Platform Details

### Linux
- Parses `/var/run/utmp` (or `/run/utmp`) binary records
- Filters to USER_PROCESS entries (type 7) by default
- Shows username, TTY, login time, and remote host

### Windows
- Uses `WTSEnumerateSessionsW` API to enumerate Terminal Services sessions
- Queries session details via `WTSQuerySessionInformationW`
- Shows domain\user, station name, connect time, client name, and session state
- Filters to active/disconnected sessions by default

### macOS
- Uses the native `who` command
- Parses output for user, TTY, login time, and source host

## MITRE ATT&CK Mapping

- **T1033** — System Owner/User Discovery
