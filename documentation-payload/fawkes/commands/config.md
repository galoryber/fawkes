+++
title = "config"
chapter = false
weight = 126
hidden = false
+++

## Summary

View or modify the agent's runtime configuration. Allows operators to adjust timing, kill dates, and working hours without rebuilding the payload.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | show | `show` displays current config, `set` modifies a value |
| key | No | | Config key to modify (required for `set`) |
| value | No | | New value (required for `set`) |

### Settable Keys

| Key | Description | Example Values |
|-----|-------------|---------------|
| sleep | Sleep interval in seconds | `30`, `60` |
| jitter | Jitter percentage (0-100) | `20`, `50` |
| killdate | Agent expiration date | `2026-03-15`, `1741036800`, `disable` |
| working_hours_start | Working hours start (HH:MM) | `09:00`, `disable` |
| working_hours_end | Working hours end (HH:MM) | `17:00`, `disable` |
| working_days | Active days (ISO: Mon=1, Sun=7) | `1,2,3,4,5`, `all` |
| default_ppid | Parent PID spoofing for run/powershell | `1234`, `0`, `disable` |

## Usage

### Show current config
```
config
config -action show
```

### Modify sleep interval
```
config -action set -key sleep -value 30
```

### Set kill date
```
config -action set -key killdate -value 2026-03-15
config -action set -key killdate -value disable
```

### Set working hours
```
config -action set -key working_hours_start -value 09:00
config -action set -key working_hours_end -value 17:00
config -action set -key working_days -value 1,2,3,4,5
```

### Set default PPID (subprocess spoofing)
```
# Find explorer.exe PID
ps explorer

# Set PPID — all run/powershell commands will appear under this parent
config -action set -key default_ppid -value 1234

# Disable PPID spoofing
config -action set -key default_ppid -value disable
```

When `default_ppid` is set, child processes spawned by `run` and `powershell` commands use PPID spoofing via `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)`. This makes child processes appear as children of the specified PID (e.g., `explorer.exe`) instead of the agent process, defeating parent-child process relationship detection. Windows only; combines with BlockDLLs if both are active (T1134.004).

## MITRE ATT&CK Mapping

- T1134.004 — Access Token Manipulation: Parent PID Spoofing (when default_ppid is set)
