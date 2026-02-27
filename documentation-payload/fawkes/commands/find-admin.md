+++
title = "find-admin"
chapter = false
weight = 150
hidden = false
+++

## Summary

Sweeps a list of hosts to discover where credentials have administrative access. Tests admin privileges via SMB (mounting the C$ admin share) and/or WinRM (executing `whoami`).

Cross-platform — works from Windows, Linux, and macOS agents. Supports pass-the-hash, CIDR notation, IP ranges, and parallel scanning.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| hosts | Yes | Target hosts — IPs, CIDR ranges (10.0.0.0/24), IP ranges (10.0.0.1-50), or hostnames (comma-separated) |
| username | Yes | Account to test (`DOMAIN\user` or `user@domain`) |
| password | No* | Password (*required unless hash is provided) |
| hash | No* | NT hash for pass-the-hash (LM:NT or just NT) |
| domain | No | Domain name (auto-detected from username format) |
| method | No | Check method: `smb`, `winrm`, or `both` (default: `smb`) |
| timeout | No | Per-host timeout in seconds (default: 5) |
| concurrency | No | Max parallel checks (default: 50) |

## Usage

### SMB admin sweep across a subnet
```
find-admin -hosts 192.168.1.0/24 -username CORP\admin -password P@ssw0rd
```

### WinRM admin check with pass-the-hash
```
find-admin -hosts dc01,dc02,dc03 -username admin@corp.local -hash aad3b435b51404ee:8846f7eaee8fb117 -method winrm
```

### Both methods on specific hosts
```
find-admin -hosts 10.0.0.1-10 -username DOMAIN\svcadmin -password Secret123 -method both
```

## Output

```
[*] Admin access sweep: 3 hosts via smb (password as NORTH\vagrant)
------------------------------------------------------------
[+] 192.168.100.52       SMB    ADMIN
[-] 192.168.100.51       SMB    no admin share
[-] 192.168.100.53       SMB    access denied
------------------------------------------------------------
[*] 1/3 hosts have admin access
```

**Result codes:**
- `ADMIN` — Credentials have administrative access on this host
- `access denied` — Authentication succeeded but account lacks admin rights
- `auth failed` — Invalid credentials for this host
- `auth error` — Authentication protocol error
- `no admin share` — C$ share not accessible (may indicate restricted admin shares)
- `unreachable` — Host did not respond on the required port (445 for SMB, 5985 for WinRM)

## OPSEC Considerations

- **SMB (port 445)**: Mounts `\\host\C$` — only local administrators can access admin shares. Generates Windows Security Event 4624 (logon) and potentially 5140 (share access)
- **WinRM (port 5985)**: Executes `whoami` via WinRM — generates Event 4624 and WinRM operational logs
- **Parallel scanning**: Default concurrency of 50 creates noticeable network traffic on large scans; reduce with `-concurrency` for stealth
- **Authentication failures**: Failed auth attempts generate Event 4625 (logon failure) — repeated failures may trigger account lockout policies

## MITRE ATT&CK Mapping

- T1021.002 — Remote Services: SMB/Windows Admin Shares
- T1021.006 — Remote Services: Windows Remote Management
- T1135 — Network Share Discovery
