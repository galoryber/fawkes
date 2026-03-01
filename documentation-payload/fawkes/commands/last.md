+++
title = "last"
chapter = false
weight = 206
hidden = false
+++

## Summary

Show recent login history and session information. Cross-platform implementation: parses utmp/wtmp on Linux, queries Security event log (Event ID 4624) on Windows, and uses the native `last` command on macOS.

Useful for understanding who has been accessing the system, identifying active administrators, and finding patterns for blending in.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| count | No | 25 | Number of login entries to show |
| user | No | | Filter by username |

## Usage

Show recent logins:
```
last
```

Show last 50 entries:
```
last -count 50
```

Filter by user:
```
last -user admin
```

## Output Format

Returns a JSON array rendered as a sortable table via browser script:
```json
[
  {
    "user": "admin",
    "tty": "pts/0",
    "from": "192.168.1.100",
    "login_time": "2025-01-15 09:30:00",
    "duration": "02:15"
  }
]
```

## Platform Details

### Linux
1. Parses `/var/log/wtmp` (historical logins) and `/var/run/utmp` (current sessions) binary records
2. Auto-detects utmp record size (supports 384, 392, 288, 292 byte variants)
3. Falls back to parsing `/var/log/auth.log` or `/var/log/secure` if wtmp is unavailable

### Windows
{{% notice info %}}Queries Security event log — may require elevated privileges{{% /notice %}}
- Queries Event ID 4624 (successful logon) from the Security event log
- Filters interactive (2), network (3), unlock (7), and RDP (10) logon types
- Skips machine accounts (ending in `$`)
- Extracts username, domain, source IP, and logon type

### macOS
- Uses the native `last` command with `-n` count and optional user filter

## MITRE ATT&CK Mapping

- **T1087.001** — Account Discovery: Local Account
