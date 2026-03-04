+++
title = "persist-enum"
chapter = false
weight = 100
hidden = false
+++

## Summary

Enumerate common Windows persistence mechanisms without making any changes. Checks registry Run keys, startup folders, Winlogon hijacks, Image File Execution Options (IFEO), AppInit_DLLs, scheduled tasks (via registry), and non-Microsoft services.

{{% notice info %}}Windows Only{{% /notice %}}

## How It Works

All enumeration is read-only — no registry writes or service modifications. Each category queries specific registry keys or filesystem paths to identify persistence entries.

### Categories

| Category | What It Checks |
|----------|---------------|
| `registry` | HKLM/HKCU Run, RunOnce, RunServices, RunServicesOnce, Shell Folders |
| `startup` | User and All Users startup folders |
| `winlogon` | Winlogon Shell, Userinit, AppInit_DLLs, TaskMan (flags non-default values) |
| `ifeo` | Image File Execution Options — Debugger entries on all subkeys |
| `appinit` | AppInit_DLLs (64-bit and WOW64) with enabled/disabled status |
| `tasks` | Scheduled tasks via TaskCache registry tree (recursive walk) |
| `services` | Non-Microsoft Win32 services (filters out svchost, lsass, dllhost, etc.) |

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| category | No | Which category to enumerate: `all` (default), `registry`, `startup`, `winlogon`, `ifeo`, `appinit`, `tasks`, `services` |

## Usage

Enumerate all persistence mechanisms:
```
persist-enum
persist-enum -category all
```

Check only registry Run keys:
```
persist-enum -category registry
```

Check scheduled tasks:
```
persist-enum -category tasks
```

## Notes

- Read-only — no modifications are made to the system
- Scheduled task enumeration reads the TaskCache registry tree, not the Task Scheduler service
- Service enumeration filters common Microsoft service paths (svchost, lsass, services.exe, dllhost, wbem, msiexec)
- Winlogon checks compare values against known defaults and only report deviations
- Useful for situational awareness before or after deploying persistence

## MITRE ATT&CK Mapping

- **T1547** — Boot or Logon Autostart Execution
- **T1053** — Scheduled Task/Job
- **T1543** — Create or Modify System Process
