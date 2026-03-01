+++
title = "schtask"
chapter = false
weight = 130
hidden = false
+++

{{% notice info %}}Windows Only{{% /notice %}}

## Summary

Create, query, run, or delete Windows scheduled tasks via Task Scheduler COM API (no subprocess creation). Uses ITaskService COM interface with XML-based task registration. Supports multiple trigger types, custom run-as accounts, and immediate execution.

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| action | choose_one | Yes | query | `create`, `query`, `delete`, `run`, or `list` |
| name | string | No* | - | Task name (e.g., `\MyTask`). *Required for all actions except `list`. |
| program | string | No* | - | Path to executable. *Required for `create`. |
| args | string | No | - | Arguments to pass to the program |
| trigger | choose_one | No | ONLOGON | When to run: `ONLOGON`, `ONSTART`, `DAILY`, `WEEKLY`, `MONTHLY`, `ONCE`, `ONIDLE` |
| time | string | No | - | Start time for time-based triggers (HH:MM format) |
| user | string | No | - | Run-as user account (e.g., `SYSTEM`, `NT AUTHORITY\SYSTEM`) |
| run_now | boolean | No | false | Execute the task immediately after creation |

## Usage

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

### Query a Task

Get detailed information about a specific task:
```
schtask -action query -name "WindowsUpdate"
```

### Run a Task

Trigger immediate execution of an existing task:
```
schtask -action run -name "WindowsUpdate"
```

### List All Tasks

Enumerate all scheduled tasks on the system:
```
schtask -action list
```

### Delete a Task

Remove a scheduled task:
```
schtask -action delete -name "WindowsUpdate"
```

### Example Output (create)
```
Created scheduled task:
  Name:    SecurityScan
  Program: C:\Windows\Temp\scan.exe
  Trigger: DAILY
```

### Example Output (query)
```
Task: SecurityScan
State: Ready
Enabled: true
Last Run Time: 2026-02-22 03:20:00
Next Run Time: 2026-02-23 09:00:00
Last Result: 0
Description: Created by Fawkes
Action Path: C:\Windows\Temp\scan.exe
```

### Output Format (list)

The `list` action returns a JSON array (rendered as a sortable table in the Mythic UI with color-coded states):

```json
[
  {"name": "SecurityScan", "state": "Ready", "enabled": "true", "next_run_time": "2026-02-23 09:00:00"}
]
```

Other actions (create, query, delete, run) return plain text status messages.

## MITRE ATT&CK Mapping

- T1053.005 — Scheduled Task/Job: Scheduled Task
