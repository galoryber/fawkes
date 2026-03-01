+++
title = "share-hunt"
chapter = false
weight = 195
hidden = false
+++

## Summary

Automated SMB share crawler that searches for sensitive files across multiple hosts. Connects to each host via SMB, enumerates accessible shares, recursively browses directories, and identifies high-value files (credentials, configs, scripts).

Supports pass-the-hash authentication and configurable file category filters. Pairs well with `lateral-check` to first identify hosts with SMB access, then hunt for interesting files.

Similar to tools like Snaffler or ShareHunter.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| hosts | Yes | - | Target hosts: single IP, comma-separated IPs, or CIDR notation |
| username | Yes | - | SMB username (DOMAIN\user or user@domain) |
| password | No* | - | SMB password (*required if hash not provided) |
| hash | No* | - | NTLM hash for pass-the-hash (hex-encoded) |
| depth | No | 3 | Maximum directory recursion depth |
| max_files | No | 500 | Maximum number of results to return |
| filter | No | all | File category filter: all, credentials, configs, code |

## Usage

Hunt across a subnet for credential files:
```
share-hunt -hosts 192.168.1.0/24 -username CORP\admin -password Pass123 -filter credentials
```

Pass-the-hash with limited depth:
```
share-hunt -hosts 10.0.0.1,10.0.0.5 -username admin -hash aad3b435b51404ee:8846f7eaee8fb117 -depth 2
```

Search specific hosts for all sensitive files:
```
share-hunt -hosts 192.168.1.100 -username CORP\svc_backup -password BackupPass1 -max_files 100
```

## File Categories

**Credentials:** *.kdbx, *.pem, *.pfx, *.ppk, *.rdp, id_rsa, *.ovpn, unattend.xml, web.config, credentials.xml, etc.

**Configs:** *.config, *.conf, *.ini, *.xml, *.json, *.yaml, appsettings.json, *.env, etc.

**Code:** *.ps1, *.bat, *.cmd, *.vbs, *.py, *.sh, etc.

**High-Value (always matched):** Files containing "passwords", "credentials", "secrets", "ntds", "sam", "backup" in name.

## Sample Output

```
=== SHARE HUNT RESULTS ===

--- 192.168.1.100 ---
  [+] [HIGH-VALUE] \\192.168.1.100\IT\Scripts\passwords.xlsx (45.2 KB, 2025-11-15)
  [+] [cred] \\192.168.1.100\IT\Certs\wildcard.pfx (3.8 KB, 2025-08-20)
  [+] [config] \\192.168.1.100\WebApps\portal\web.config (2.1 KB, 2025-12-01)
  [+] [code] \\192.168.1.100\IT\Scripts\deploy.ps1 (8.4 KB, 2026-01-10)
  (4 files found)

--- 192.168.1.101 ---
  [!] Error: SMB auth: Access is denied

--- 2 host(s) scanned, 4 file(s) found ---
--- 1 host(s) had errors ---
```

## MITRE ATT&CK Mapping

- **T1135** — Network Share Discovery
- **T1039** — Data from Network Shared Drive
