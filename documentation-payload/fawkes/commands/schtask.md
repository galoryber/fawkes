+++
title = "schtask"
chapter = false
weight = 130
hidden = false
+++

## Summary

Manage scheduled tasks across Windows and Linux. On Windows, uses Task Scheduler COM API (no subprocess creation). On Linux, enumerates and manages crontab entries, systemd timers, and at jobs.

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| action | choose_one | Yes | query | `create`, `query`, `delete`, `run`, `list`, `enable`, `disable`, or `stop` |
| name | string | No* | - | Task name. *Required for all actions except `list`. |
| program | string | No* | - | Path to executable. *Required for `create`. |
| args | string | No | - | Arguments to pass to the program |
| trigger | choose_one | No | ONLOGON | When to run. Windows: `ONLOGON`, `ONSTART`, `DAILY`, `WEEKLY`, `MONTHLY`, `ONCE`, `ONIDLE`. Linux: same plus `systemd` (timer unit), `at` (one-shot) |
| time | string | No | - | Start time for time-based triggers (HH:MM format) |
| user | string | No | - | Run-as user account. Windows: `SYSTEM`, etc. Linux: target user for crontab |
| run_now | boolean | No | false | Execute the task immediately after creation (Windows only) |
| filter | string | No | - | Case-insensitive substring filter on task name (used with `list` action) |

## Windows Usage

### Create a Scheduled Task

Create a task that runs on user logon:
```
schtask -action create -name "WindowsUpdate" -program "C:\Windows\Temp\svc.exe" -trigger ONLOGON
```

Create a task that runs daily at 9 AM as SYSTEM:
```
schtask -action create -name "SecurityScan" -program "C:\Windows\Temp\scan.exe" -trigger DAILY -time 09:00 -user SYSTEM
```

Create and run immediately:
```
schtask -action create -name "Maintenance" -program "C:\Windows\Temp\payload.exe" -trigger ONCE -time 23:59 -run_now true
```

### Query, List, Enable/Disable, Stop, Delete

```
schtask -action query -name "WindowsUpdate"
schtask -action list -filter "Update"
schtask -action disable -name "WindowsUpdate"
schtask -action enable -name "WindowsUpdate"
schtask -action run -name "WindowsUpdate"
schtask -action stop -name "SecurityScan"
schtask -action delete -name "WindowsUpdate"
```

## Linux Usage

### List All Scheduled Tasks

Enumerates crontab entries (user + system + cron.d + periodic), systemd timers, and at jobs:
```
schtask -action list
schtask -action list -filter "backup"
```

### Query a Systemd Timer or At Job

```
schtask -action query -name "apt-daily.timer"
schtask -action query -name "at-job-5"
```

### Create a Cron Job

Uses standard cron schedule derived from trigger type:
```
schtask -action create -program "/usr/local/bin/backup.sh" -trigger DAILY -time 02:00 -name "nightly-backup"
```

### Create a Systemd Timer

```
schtask -action create -program "/usr/local/bin/check.sh" -trigger systemd -name "health-check" -time 06:00
```

### Create an At Job (One-Shot)

```
schtask -action create -program "/usr/local/bin/task.sh" -trigger at -time 14:30
```

### Delete a Scheduled Task

Cron entry (by name/marker):
```
schtask -action delete -name "nightly-backup"
```

Systemd timer:
```
schtask -action delete -name "health-check.timer"
```

At job:
```
schtask -action delete -name "at-job-5"
```

### Enable/Disable Systemd Timers

```
schtask -action enable -name "apt-daily.timer"
schtask -action disable -name "apt-daily.timer"
```

### Run/Stop Systemd Services

```
schtask -action run -name "health-check"
schtask -action stop -name "health-check"
```

## Example Output

### List (JSON array, rendered as table in Mythic UI)

```json
[
  {"name": "crontab(root): */5 * * * * /usr/bin/check-updates", "state": "Active", "type": "crontab"},
  {"name": "apt-daily.timer -> apt-daily.service [system]", "state": "waiting", "type": "systemd-timer", "next_run_time": "Thu 2026-05-22 09:00:00 CDT"},
  {"name": "at-job-3", "state": "queued", "type": "at", "next_run_time": "Thu May 22 14:30:00 2026"}
]
```

### Query (systemd timer)

```
Timer: apt-daily.timer
Description: Daily apt download activities
LoadState: loaded
ActiveState: waiting
SubState: waiting
TimersCalendar: { OnCalendar=*-*-* 6,18:00:00 }
```

## Notes

- **Linux list** enumerates: user crontab, `/etc/crontab`, `/etc/cron.d/*`, `/etc/cron.{hourly,daily,weekly,monthly}/*`, all systemd timers (system + user), and at queue
- **Systemd timer creation** writes `.timer` and `.service` unit files; root uses `/etc/systemd/system`, non-root uses `~/.config/systemd/user`
- **Cron entry deletion** matches by name marker comment (`# name`) or command substring
- **enable/disable/run/stop** on Linux operate on systemd timer/service units

## MITRE ATT&CK Mapping

- T1053.005 -- Scheduled Task/Job: Scheduled Task (Windows)
- T1053.003 -- Scheduled Task/Job: Cron (Linux)
- T1053.006 -- Scheduled Task/Job: Systemd Timers (Linux)
- T1562.001 -- Impair Defenses: Disable or Modify Tools (disable action)
