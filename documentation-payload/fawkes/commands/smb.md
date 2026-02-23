+++
title = "smb"
chapter = false
weight = 165
hidden = false
+++

## Summary

SMB2 file operations on remote network shares. Connect to Windows shares using NTLM authentication and perform file operations: list shares, browse directories, read files, write files, and delete files.

Uses the `go-smb2` library for SMB2 protocol operations (pure Go, CGO_ENABLED=0). Works cross-platform — agent running on any OS can access remote Windows shares.

## Arguments

Argument | Required | Description
---------|----------|------------
action | Yes | Operation: `shares` (list shares), `ls` (list directory), `cat` (read file), `upload` (write file), `rm` (delete file)
host | Yes | Target host IP or hostname
username | Yes | Username for NTLM auth (supports `DOMAIN\user` or `user@domain` format)
password | Yes | Password for NTLM auth
domain | No | NTLM domain (auto-detected from username if `DOMAIN\user` or `user@domain` format)
share | Conditional | Share name (e.g., `C$`, `ADMIN$`, `SYSVOL`). Required for ls, cat, upload, rm.
path | Conditional | Path within the share. Required for cat, upload, rm. Optional for ls.
content | Conditional | File content to write (required for upload action)
port | No | SMB port (default: 445)

## Usage

List available shares:
```
smb -action shares -host 192.168.1.1 -username admin -password pass -domain CORP
```

Browse a directory:
```
smb -action ls -host 192.168.1.1 -share C$ -path Users -username CORP\admin -password pass
```

Read a file:
```
smb -action cat -host 192.168.1.1 -share C$ -path Users/Public/file.txt -username admin@corp.local -password pass
```

Write a file:
```
smb -action upload -host 192.168.1.1 -share C$ -path Users/Public/payload.txt -content "data here" -username admin -password pass -domain CORP
```

Delete a file:
```
smb -action rm -host 192.168.1.1 -share C$ -path Users/Public/payload.txt -username admin -password pass -domain CORP
```

## Example Output

### List Shares
```
[*] Shares on \\192.168.100.52 (5 found)
----------------------------------------
  \\192.168.100.52\ADMIN$
  \\192.168.100.52\C$
  \\192.168.100.52\IPC$
  \\192.168.100.52\NETLOGON
  \\192.168.100.52\SYSVOL
```

### List Directory
```
[*] \\192.168.100.52\C$\Users (4 entries)
Size          Modified              Name
------------------------------------------------------------
0 B           2026-02-20 10:15:30   Administrator/
0 B           2025-10-08 04:35:12   Public/
0 B           2026-01-15 08:22:45   setup/
0 B           2025-10-08 04:35:12   Default/
```

## MITRE ATT&CK Mapping

- **T1021.002** - Remote Services: SMB/Windows Admin Shares

{{% notice info %}}Cross-Platform — works on Windows, Linux, and macOS{{% /notice %}}
