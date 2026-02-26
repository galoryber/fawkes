+++
title = "argue"
chapter = false
weight = 160
hidden = false
+++

## Summary

Execute a command with spoofed process arguments. Creates the process suspended with fake command-line arguments (which are logged by Sysmon Event ID 1, ETW, and EDR telemetry), then patches the PEB `CommandLine` to the real command before resuming. The process executes the real command while logs show the spoofed arguments.

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| command | Yes | — | The real command to execute (e.g., `cmd.exe /c whoami /all`) |
| spoof | No | exe name only | Fake command line shown in event logs. Should use the same executable as the real command. |

## Usage

### Basic usage (executable name only in logs)
```
argue -command "cmd.exe /c net user /domain"
```
Sysmon logs: `cmd.exe` | Process executes: `cmd.exe /c net user /domain`

### Custom spoof string
```
argue -command "cmd.exe /c whoami /all" -spoof "cmd.exe /c echo hello"
```
Sysmon logs: `cmd.exe /c echo hello` | Process executes: `cmd.exe /c whoami /all`

### Hide PowerShell commands
```
argue -command "powershell.exe -nop -c Get-Process" -spoof "powershell.exe -nop -c Get-Date"
```
Sysmon logs: `powershell.exe -nop -c Get-Date` | Process executes: `powershell.exe -nop -c Get-Process`

### Hide sensitive reconnaissance
```
argue -command "cmd.exe /c net group \"Domain Admins\" /domain" -spoof "cmd.exe /c hostname"
```

## How It Works

1. Process is created with `CREATE_SUSPENDED` flag using the **spoofed** command line
2. Sysmon Event ID 1 (Process Create) logs the spoofed command line at creation time
3. The PEB's `RTL_USER_PROCESS_PARAMETERS.CommandLine` is patched to the **real** command
4. The main thread is resumed — the process reads its command line from PEB via `GetCommandLineW()`
5. Process executes the real command; output is captured and returned

## MITRE ATT&CK Mapping

- **T1564.010** — Hide Artifacts: Process Argument Spoofing

## Notes

- The spoof command must use the same executable as the real command (automatically enforced)
- Works best with `cmd.exe` and `powershell.exe` which read command lines from PEB at runtime
- If the real command is longer than the spoof command, new memory is allocated in the target process
- Output is captured via pipe redirection, same as the `run` command
- 30-second timeout on process execution
- Does not require elevation — works at any privilege level
- Complements `auditpol` (disable command-line logging) and `amcache` (clear execution history) for comprehensive opsec
