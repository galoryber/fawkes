+++
title = "last"
chapter = false
weight = 206
hidden = false
+++

## Summary

Show login history, failed login attempts, and system boot/shutdown/crash events. Cross-platform implementation: parses utmp/wtmp/btmp on Linux, queries Security and System event logs on Windows, and uses the native `last` command and unified log on macOS.

Useful for understanding who has been accessing the system, identifying active administrators, detecting brute force attempts, determining system uptime/reboot patterns, and finding patterns for blending in.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | logins | `logins`: login history. `failed`: failed login attempts. `reboot`: system boot/shutdown/crash events |
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

Show system boot/shutdown events:
```
last -action reboot
```

Show last 10 reboots:
```
last -action reboot -count 10
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

For reboot events, the `tty` field indicates the event type (`boot`, `shutdown`, `crash`, `restart`).

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

**Reboot action:**
1. Parses `/var/log/wtmp` for BOOT_TIME (ut_type=2) and shutdown (RUN_LVL with "shutdown" in ut_line) records
2. Shows boot and clean shutdown events with timestamps

### Windows
{{% notice info %}}Queries event logs — may require elevated privileges{{% /notice %}}

**Logins action:**
- Queries Event ID 4624 (successful logon) from the Security event log
- Filters interactive (2), network (3), unlock (7), and RDP (10) logon types
- Skips machine accounts (ending in `$`)

**Failed action:**
- Queries Event ID 4625 (failed logon) from the Security event log
- Skips machine accounts (ending in `$`)
- Extracts username, domain, and source IP

**Reboot action:**
- Queries the System event log for:
  - Event ID 6005 — Event Log service started (system boot)
  - Event ID 6006 — Event Log service stopped (clean shutdown)
  - Event ID 6008 — Unexpected shutdown (crash/power loss)
  - Event ID 1074 — User-initiated restart/shutdown (includes requesting user)

### macOS
**Logins action:**
- Uses the native `last` command with `-n` count and optional user filter

**Failed action:**
- Queries macOS unified log for authentication failure events (last 7 days)
- Falls back to parsing `/var/log/secure.log` if unified log is unavailable

**Reboot action:**
- Uses `last reboot` to enumerate system boot events from wtmp

## MITRE ATT&CK Mapping

- **T1087.001** — Account Discovery: Local Account
- **T1110** — Brute Force (detection via failed login enumeration)
- **T1082** — System Information Discovery (reboot/uptime history)
