+++
title = "linux-logs"
chapter = false
weight = 111
hidden = false
+++

## Summary

Linux log file enumeration, reading, and tampering. Lists log files with metadata, reads text logs with search filtering, parses binary login records (wtmp/btmp/utmp), and supports clearing, selective line removal, and secure shredding of log files. Designed for anti-forensics and indicator removal on Linux targets.

{{% notice info %}}Linux Only{{% /notice %}}

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | Yes | `list`: enumerate log files. `read`: read text log. `logins`: parse binary login records. `clear`: truncate to zero. `truncate`: remove matching lines. `shred`: 3-pass zero overwrite. |
| file | Read/Clear/Truncate/Shred | Path to the log file (e.g., `/var/log/auth.log`) |
| lines | No | Maximum lines/records to display (default: 50) |
| search | Read/Truncate | Filter string — `read` shows matching lines, `truncate` removes matching lines |
| user | No | Filter login records by username (logins action) |

## Usage

```
# List all log files with sizes and modification times
linux-logs -action list

# Read last 10 lines of auth.log
linux-logs -action read -file /var/log/auth.log -lines 10

# Read syslog filtered by keyword
linux-logs -action read -file /var/log/syslog -search "failed"

# Parse login records (wtmp/btmp/utmp)
linux-logs -action logins -lines 20

# Parse login records filtered by user
linux-logs -action logins -user root

# Clear a log file (truncate to 0 bytes, preserves inode)
linux-logs -action clear -file /var/log/auth.log

# Remove specific lines from a log (selective truncation)
linux-logs -action truncate -file /var/log/auth.log -search "192.168.1.100"

# Securely shred a log file (3-pass zero overwrite)
linux-logs -action shred -file /var/log/auth.log
```

## List Output

The `list` action enumerates three categories:
- **Log Files** — Common text logs (`/var/log/auth.log`, `syslog`, `messages`, `kern.log`, etc.)
- **Login Record Files** — Binary login records (`/var/log/wtmp`, `/var/log/btmp`, `/var/run/utmp`)
- **Rotated Logs** — Compressed and numbered rotated logs (`/var/log/*.gz`, `/var/log/*.1`)

Each file shows size in bytes and last modification time.

## Login Records

The `logins` action directly parses binary utmp/wtmp/btmp files (384-byte records on x86_64) without invoking `last`, `utmpdump`, or any external tools. Fields parsed:

| Field | Description |
|-------|-------------|
| Timestamp | Login/logout time |
| Type | RUN_LVL, BOOT, INIT, LOGIN, USER, DEAD |
| User | Username |
| Host | Remote host |
| PID | Process ID |
| Line | Terminal line (pts/0, etc.) |

## OPSEC Considerations

- `list` and `read` use only filesystem operations — no subprocess execution
- `logins` parses binary files directly — does not invoke `last`, `utmpdump`, or other tools
- `clear` truncates the file in-place, preserving the inode number (avoids detection by inode change)
- `truncate` rewrites the file to remove specific lines — file size change may be noticed
- `shred` performs 3-pass zero overwrite before truncation — prevents recovery but file metadata still exists
- Modifying system logs typically requires root or appropriate group membership (e.g., `adm`)
- Log rotation (logrotate) may create new copies — consider checking rotated files too
- syslog daemon may reopen the file handle after truncation

## MITRE ATT&CK Mapping

- **T1070.002** — Indicator Removal: Clear Linux or Mac System Logs
