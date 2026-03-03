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

Execute a PowerShell command or script directly via `powershell.exe`. Uses OPSEC-hardened invocation flags: abbreviated parameter names and randomized flag ordering to defeat SIEM/EDR signature matching.

Supports **encoded command mode** (`-EncodedCommand`) which base64-encodes the command in UTF-16LE format, hiding the actual command text from process tree listings (e.g., Sysmon Event ID 1, Process Explorer, tasklist).

### Arguments

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| command | String | Yes | The PowerShell command or script to execute |
| encoded | Boolean | No | Use `-EncodedCommand` mode to hide command from process tree (default: false) |

## Usage

Simple commands (plain text input):
```
powershell Get-Date
powershell $env:COMPUTERNAME
powershell Get-Process | Select-Object -First 5 Name,Id
```

Encoded command mode (hides command from process tree):
```
powershell {"command": "Get-Process | Where-Object { $_.CPU -gt 100 }", "encoded": true}
```

Script blocks:
```
powershell Get-ChildItem C:\Users -Recurse -Filter *.txt | Select-Object FullName
```

Environment enumeration:
```
powershell Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version
```

## OPSEC Notes

- **Abbreviated flags**: Uses `-nop`, `-noni`, `-ep bypass` instead of full flag names (`-NoProfile`, `-NonInteractive`, `-ExecutionPolicy Bypass`) to avoid matching standard SIEM detection rules (Sigma `proc_creation_win_powershell_suspicious_flags`, Elastic `powershell_suspicious_execution`)
- **Randomized flag ordering**: Flag order changes on every invocation to defeat fingerprinting
- **Encoded command mode**: When `encoded=true`, the command is converted to UTF-16LE base64 and passed via `-enc`, hiding the actual command text from process argument listings
- For operations that need to avoid `powershell.exe` entirely, use `startclr` (executes .NET assemblies via the CLR without spawning PowerShell)

## MITRE ATT&CK Mapping

- T1059.001 — Command and Scripting Interpreter: PowerShell
- T1027.010 — Obfuscated Files or Information: Command Obfuscation (encoded command mode)
