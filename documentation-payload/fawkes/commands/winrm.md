+++
title = "winrm"
chapter = false
weight = 168
hidden = false
+++

## Summary

Execute commands on remote Windows hosts via WinRM (Windows Remote Management) with NTLM authentication. Supports both `cmd.exe` and PowerShell shells. Supports pass-the-hash (PTH) — authenticate with an NT hash instead of a plaintext password.

Uses the `masterzen/winrm` library for WinRM protocol operations with a custom NTLM transport for PTH support (pure Go, CGO_ENABLED=0). Works cross-platform — agent running on any OS can execute commands on remote Windows hosts with WinRM enabled.

## Arguments

Argument | Required | Description
---------|----------|------------
host | Yes | Target host IP or hostname
username | Yes | Username for NTLM auth (supports `DOMAIN\user` format)
password | No* | Password for NTLM auth (*required unless `-hash` is provided)
hash | No* | NT hash for pass-the-hash (hex, e.g., `aad3b435...:8846f7ea...` or just the NT hash)
command | Yes | Command to execute on the remote host
shell | No | Shell type: `cmd` (default) or `powershell`
port | No | WinRM port (default: 5985 for HTTP, 5986 for HTTPS)
use_tls | No | Use HTTPS/TLS connection (default: false)
timeout | No | Command timeout in seconds (default: 60)

## Usage

Run a command via cmd.exe:
```
winrm -host 192.168.1.1 -username admin -password pass -command "whoami"
```

Run a PowerShell command:
```
winrm -host 192.168.1.1 -username admin -password pass -command "Get-Process | Select-Object -First 5 Name, Id" -shell powershell
```

Domain user authentication:
```
winrm -host 192.168.1.1 -username DOMAIN\admin -password pass -command "hostname"
```

Use HTTPS (port 5986):
```
winrm -host 192.168.1.1 -username admin -password pass -command "ipconfig" -use_tls true -port 5986
```

### Pass-the-Hash (PTH)

Use `-hash` instead of `-password` with an NT hash:
```
winrm -host 192.168.1.1 -username admin -hash 8846f7eaee8fb117ad06bdd830b7586c -command "whoami"
```

PTH with PowerShell:
```
winrm -host 192.168.1.1 -username admin -hash aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c -command "hostname" -shell powershell
```

## Example Output

### cmd.exe (password)
```
[*] WinRM vagrant@192.168.100.52:5985 (cmd, password)
[*] Command: whoami
[*] Exit Code: 0
------------------------------------------------------------
north\vagrant
```

### cmd.exe (pass-the-hash)
```
[*] WinRM eddard.stark@192.168.100.52:5985 (cmd, PTH)
[*] Command: whoami
[*] Exit Code: 0
------------------------------------------------------------
north\eddard.stark
```

### PowerShell
```
[*] WinRM vagrant@192.168.100.52:5985 (powershell)
[*] Command: Get-Process | Select-Object -First 5 Name, Id | Format-Table
[*] Exit Code: 0
------------------------------------------------------------

Name      Id
----      --
cmd     2628
conhost 1444
conhost 1532
conhost 1792
csrss     35
```

## MITRE ATT&CK Mapping

- **T1021.006** - Remote Services: Windows Remote Management
- **T1550.002** - Use Alternate Authentication Material: Pass the Hash

{{% notice info %}}Cross-Platform — works on Windows, Linux, and macOS{{% /notice %}}
