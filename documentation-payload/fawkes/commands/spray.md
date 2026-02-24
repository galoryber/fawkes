+++
title = "spray"
chapter = false
weight = 102
hidden = false
+++

## Summary

Password spray or Kerberos user enumeration against Active Directory. Spray via Kerberos pre-auth, LDAP simple bind, or SMB NTLM authentication. Enumerate validates AD usernames without credentials via Kerberos AS-REQ. Supports configurable delay and jitter to avoid triggering account lockout policies.

Cross-platform — works from Windows, Linux, and macOS agents.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | Yes | Action: `kerberos`, `ldap`, `smb`, or `enumerate` |
| server | Yes | Target Domain Controller or server IP/hostname |
| domain | Yes | Domain name (e.g., `CORP.LOCAL`) |
| users | Yes | Newline-separated list of usernames |
| password | No* | Password to spray (*required for kerberos/ldap/smb, not needed for enumerate) |
| delay | No | Delay between attempts in milliseconds (default: 0) |
| jitter | No | Jitter percentage for delay randomization, 0-100 (default: 0) |
| port | No | Custom port (default: 88 for Kerberos, 389/636 for LDAP, 445 for SMB) |
| use_tls | No | Use TLS/LDAPS for LDAP spray (default: false) |

## Protocols

### Kerberos (Recommended)
Attempts Kerberos AS-REQ pre-authentication against the KDC (port 88). This is the fastest and quietest spray method — generates Event ID 4771 (pre-auth failure) rather than 4625 (logon failure).

### LDAP
Attempts LDAP simple bind against the DC (port 389 or 636 for LDAPS). Uses UPN format (`user@domain`) automatically. Useful when Kerberos port is not directly accessible.

### SMB
Attempts SMB2 NTLM authentication against the target (port 445). Tests actual SMB access, useful for validating credentials against file servers. Generates Event ID 4625.

### Enumerate
Validates AD usernames via Kerberos AS-REQ without pre-authentication data (port 88). No credentials required. The KDC response code distinguishes valid from invalid usernames:
- **KDC_ERR_PREAUTH_REQUIRED (25)** — user exists (pre-auth required)
- **KDC_ERR_C_PRINCIPAL_UNKNOWN (6)** — user does not exist
- **Valid AS-REP** — user exists and is AS-REP roastable (no pre-auth required)

## Usage

### Kerberos spray with delay
```
spray -action kerberos -server 192.168.1.1 -domain CORP.LOCAL -users "admin\njsmith\njdoe" -password Summer2026! -delay 1000 -jitter 25
```

### LDAP spray
```
spray -action ldap -server dc01 -domain corp.local -users "svc_backup\nadmin\ntest" -password Password1
```

### SMB spray
```
spray -action smb -server fileserver -domain CORP -users "alice\nbob\ncharlie" -password Welcome1!
```

### User enumeration (no credentials needed)
```
spray -action enumerate -server dc01 -domain corp.local -users "admin\njsmith\nsvc_backup\nfake.user"
```

## Output

The command outputs results in a structured format:
- `[+] VALID: username — Authentication successful` — Valid credential found
- `[!] LOCKED: username — Account locked out` — Account lockout detected (spray aborts)
- Summary line with valid/locked/failed counts

### Account Lockout Protection
- The spray automatically **aborts** if an account lockout is detected (Kerberos KDC_ERR_CLIENT_REVOKED, LDAP 775, SMB STATUS_ACCOUNT_LOCKED_OUT)
- Use `-delay` with `-jitter` to slow down attempts and avoid triggering lockout thresholds
- Expired passwords and must-change-password accounts are reported as informational (credential is technically valid)

## OPSEC Considerations

- **Kerberos** is the quietest option — pre-auth failures (Event 4771) are less commonly monitored than logon failures (Event 4625)
- **LDAP** and **SMB** generate standard Windows logon events (4625) that are commonly monitored by SOCs
- Use delay and jitter to stay below lockout thresholds (typical AD default: 10 attempts in 30 minutes)
- Consider spraying during business hours when authentication traffic is expected
- Each protocol creates separate network connections per attempt

## MITRE ATT&CK Mapping

- T1110.003 — Brute Force: Password Spraying
- T1589.002 — Gather Victim Identity Information: Email Addresses (user enumeration)
