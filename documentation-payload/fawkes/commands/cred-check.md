+++
title = "cred-check"
chapter = false
weight = 196
hidden = false
+++

## Summary

Test credentials (password or NTLM hash) against multiple protocols on target hosts. Validates authentication against SMB, WinRM, and LDAP in parallel.

Completes the lateral movement recon workflow:
1. `lateral-check` — identify open services
2. `cred-check` — validate credentials against those services
3. `share-hunt` / `psexec` / `winrm` — exploit validated access

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | check | `check`: test specific credentials. `verify-all`: test all vault credentials against discovered hosts. |
| hosts | Yes* | - | Target hosts: single IP, comma-separated IPs, or CIDR notation (*not required for verify-all) |
| username | Yes* | - | Username (DOMAIN\user or user@domain) (*not required for verify-all) |
| password | No* | - | Password (*required if hash not provided) |
| hash | No* | - | NTLM hash for pass-the-hash on SMB (hex-encoded) |
| timeout | No | 5 | Per-check timeout in seconds |

## Usage

Test credentials on a single host:
```
cred-check -hosts 192.168.1.100 -username CORP\admin -password Pass123
```

Test across a subnet with pass-the-hash:
```
cred-check -hosts 10.0.0.0/24 -username administrator -hash aad3b435b51404ee:8846f7eaee8fb117
```

### Verify all vault credentials (subtask chain)
```
cred-check -action verify-all
```
Queries the Mythic credential vault for all stored plaintext passwords and NTLM hashes, discovers active callback hosts, and tests each credential against all hosts in parallel. Results are aggregated showing valid/invalid/error per credential. Max 10 credentials tested per run.

## Protocols Tested

| Protocol | Port | Auth Method |
|----------|------|-------------|
| SMB | 445 | NTLM (password or hash) |
| WinRM | 5985 | HTTP Basic Auth |
| LDAP | 389 | Simple Bind |

## Sample Output

```
=== CREDENTIAL CHECK ===
User: CORP\admin

--- 192.168.1.100 ---
  [+] SMB          authenticated (4 shares visible)
  [+] WinRM        authenticated (HTTP 200)
  [+] LDAP         authenticated (LDAP bind success)

--- 192.168.1.101 ---
  [+] SMB          authenticated (2 shares visible)
  [-] WinRM        port 5985 closed/unreachable
  [-] LDAP         auth failed (invalid credentials)

--- 2 host(s) checked, 4 successful auth(s) ---
```

## MITRE ATT&CK Mapping

- **T1110.001** — Brute Force: Password Guessing
- **T1078** — Valid Accounts
