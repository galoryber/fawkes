+++
title = "suspend"
chapter = false
weight = 192
hidden = false
+++

## Summary

Suspend or resume a process by PID. Tactically pause security tools during sensitive operations.

Cross-platform (Windows, Linux, macOS).

- **Windows:** Uses `NtSuspendProcess` / `NtResumeProcess` (ntdll.dll)
- **Linux/macOS:** Uses `SIGSTOP` / `SIGCONT` signals

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | suspend | `suspend` to freeze, `resume` to continue |
| pid | Yes | - | Process ID to suspend or resume |

## Usage

### Suspend a process
```
suspend -pid 1234
```

### Resume a suspended process
```
suspend -action resume -pid 1234
```

## Tactical Use Cases

### Pause EDR during sensitive operations
```
# 1. Identify EDR process
ps -v | grep -i defender
# 2. Suspend it
suspend -pid <edr_pid>
# 3. Perform sensitive operation (hashdump, injection, etc.)
hashdump
# 4. Resume to avoid detection of stopped service
suspend -action resume -pid <edr_pid>
```

### Freeze process for memory inspection
```
suspend -pid 5678
mem-scan -pid 5678 -pattern "password"
suspend -action resume -pid 5678
```

## Notes

- Suspended processes are visible in task manager/process listings (state shows as "Suspended")
- On Windows, requires `PROCESS_SUSPEND_RESUME` access right
- On Linux/macOS, requires appropriate permissions (same user or root)
- `SIGSTOP` cannot be caught or ignored by the target process
- Suspending critical system processes may cause instability

## MITRE ATT&CK Mapping

- **T1562.001** — Impair Defenses: Disable or Modify Tools
