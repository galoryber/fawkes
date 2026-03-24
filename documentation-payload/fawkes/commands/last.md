+++
title = "last"
chapter = false
weight = 206
hidden = false
+++

## Summary

Show login history and failed login attempts. Cross-platform implementation: parses utmp/wtmp/btmp on Linux, queries Security event log (Event IDs 4624/4625) on Windows, and uses the native `last` command on macOS.

Useful for understanding who has been accessing the system, identifying active administrators, detecting brute force attempts, and finding patterns for blending in.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | logins | `logins`: login history. `failed`: failed login attempts |
| count | No | 25 | Number of entries to show |
| user | No | | Filter by username |

## Usage

Show recent logins:
```
last
```

Show last 50 login entries:
```
last -action logins -count 50
```

Show failed login attempts:
```
last -action failed
```

Filter failed logins by user:
```
last -action failed -user admin -count 20
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
**Logins action:**
1. Parses `/var/log/wtmp` (historical logins) and `/var/run/utmp` (current sessions) binary records
2. Auto-detects utmp record size (supports 384, 392, 288, 292 byte variants)
3. Falls back to parsing `/var/log/auth.log` or `/var/log/secure` if wtmp is unavailable

**Failed action:**
1. Parses `/var/log/btmp` (failed login attempts, same utmp binary format)
2. Requires root to read btmp; falls back to parsing auth.log for "Failed password" / "authentication failure" lines
3. Results include the attempted username, source IP, and timestamp

### Windows
{{% notice info %}}Queries Security event log — may require elevated privileges{{% /notice %}}

**Logins action:**
- Queries Event ID 4624 (successful logon) from the Security event log
- Filters interactive (2), network (3), unlock (7), and RDP (10) logon types
- Skips machine accounts (ending in `$`)

**Failed action:**
- Queries Event ID 4625 (failed logon) from the Security event log
- Skips machine accounts (ending in `$`)
- Extracts username, domain, and source IP

### macOS
- Uses the native `last` command with `-n` count and optional user filter
- Failed action: not yet implemented

## MITRE ATT&CK Mapping

- **T1087.001** — Account Discovery: Local Account
- **T1110** — Brute Force (detection via failed login enumeration)
