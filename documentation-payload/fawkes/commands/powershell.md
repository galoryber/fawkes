+++
title = "powershell"
chapter = false
weight = 104
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Execute a PowerShell command or script directly via `powershell.exe`. Runs with `-NoProfile -NonInteractive -ExecutionPolicy Bypass` flags for consistent behavior.

This is a convenience command that provides a cleaner interface than `run powershell -Command ...`. Output from both stdout and stderr is captured.

### Arguments

| Parameter | Type | Description |
|-----------|------|-------------|
| command | String | The PowerShell command or script to execute |

## Usage

Simple commands:
```
powershell Get-Date
powershell $env:COMPUTERNAME
powershell Get-Process | Select-Object -First 5 Name,Id
```

Script blocks:
```
powershell Get-ChildItem C:\Users -Recurse -Filter *.txt | Select-Object FullName
```

Environment enumeration:
```
powershell Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version
```

## MITRE ATT&CK Mapping

- T1059.001 — Command and Scripting Interpreter: PowerShell
