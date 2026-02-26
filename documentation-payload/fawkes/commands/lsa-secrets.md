+++
title = "lsa-secrets"
chapter = false
weight = 157
hidden = false
+++

## Summary

Extract LSA secrets and cached domain credentials from the Windows SECURITY registry hive. LSA secrets contain service account passwords (plaintext), machine account credentials, DPAPI backup keys, and cached domain logon credentials (DCC2/MSCacheV2 format).

{{% notice info %}}Windows Only{{% /notice %}}

{{% notice warning %}}Requires SYSTEM privileges. Use `getsystem` before running this command.{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action   | Yes      | dump    | `dump` — extract all LSA secrets; `cached` — extract cached domain credentials only (DCC2 hashcat format) |

## Usage

### Dump All LSA Secrets
```
lsa-secrets -action dump
```

Extracts and decrypts all secrets from `SECURITY\Policy\Secrets\`:
- **_SC_\<service\>**: Service account passwords (plaintext)
- **$MACHINE.ACC**: Machine account password/hash
- **DPAPI_SYSTEM**: DPAPI user and machine backup keys
- **NL$KM**: Cached credential encryption key
- **DefaultPassword**: Auto-logon password (if configured)

### Extract Cached Domain Credentials
```
lsa-secrets -action cached
```

Extracts cached domain logon credentials in DCC2/MSCacheV2 format:
- Output format: `$DCC2$<iterations>#<username>#<hash>`
- Crack with: `hashcat -m 2100 hashes.txt wordlist.txt`
- Default iteration count: 10240

## MITRE ATT&CK Mapping

- **T1003.004** — OS Credential Dumping: LSA Secrets
- **T1003.005** — OS Credential Dumping: Cached Domain Credentials
