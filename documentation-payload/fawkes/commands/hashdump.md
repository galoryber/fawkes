+++
title = "hashdump"
chapter = false
weight = 105
hidden = false
+++

## Summary

Extract local account password hashes from the system. Supports Windows (SAM database), Linux (/etc/shadow), and macOS (Directory Services).

### Windows — SAM Hash Extraction (`-action dump`)

{{% notice info %}}Windows Only{{% /notice %}}

Reads and decrypts the SYSTEM and SAM registry hives in-memory to extract NTLM password hashes. No files are written to disk.

Output format matches the standard `pwdump` format:
```
username:RID:LM_hash:NT_hash:::
```

**How It Works:**

1. **Boot Key Extraction** — Reads class names from four LSA subkeys (`JD`, `Skew1`, `GBG`, `Data`) under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` and applies a permutation to derive the 16-byte boot key.
2. **Hashed Boot Key Derivation** — Reads the SAM `F` value from `HKLM\SAM\SAM\Domains\Account` and decrypts it using the boot key. Supports both RC4 (SAM revision 1, pre-Win10) and AES-128-CBC (SAM revision 2, Win10+).
3. **User Enumeration** — Enumerates user RID subkeys under `HKLM\SAM\SAM\Domains\Account\Users` and reads each user's `V` value.
4. **Hash Decryption** — Decrypts each user's NT and LM hashes using the hashed boot key and RID-derived DES keys.

**Requirements:**
- Administrator privileges (High integrity for SeBackupPrivilege)
- SYSTEM token recommended — run `getsystem` first

### Windows — In-Situ Logon Session Enumeration (`-action insitu`)

{{% notice info %}}Windows Only{{% /notice %}}

Enumerates active logon sessions from the live LSASS process without writing to disk. Uses `LsaEnumerateLogonSessions` and `LsaGetLogonSessionData` to retrieve session metadata for all currently authenticated users.

Reports username, domain, UPN, logon type, authentication package, session ID, logon time, and DNS domain for each active session. Useful for identifying domain users logged on to a system when SAM dump would only reveal local accounts.

**Output (JSON array):**
```json
[
  {
    "logon_id": "0:1234567",
    "username": "jdoe",
    "domain": "CORP",
    "upn": "jdoe@corp.example.com",
    "logon_type": "Interactive",
    "auth_package": "Kerberos",
    "session": 1,
    "logon_time": "2026-05-05 09:00:00 UTC",
    "dns_domain": "corp.example.com"
  }
]
```

**Phase 2 (planned):** NT hash and WDigest cleartext extraction from MSV1_0 credential cache via direct LSASS memory read.

**Requirements:**
- Administrator privileges

### Windows — In-Situ LSASS Memory Walk (`-action insitu-full`)

{{% notice info %}}Windows Only{{% /notice %}}

Phase 2B in-situ analysis: opens `lsass.exe` with `PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION`, locates `lsasrv.dll` in the loader list, pattern-scans the mapped image for the mimikatz `LogonSessionList` signature, decodes the RIP-relative `MOV r8,[mem]` displacement, and walks the doubly-linked `LogonSessionList` head sentinel via repeated `ReadProcessMemory` calls. Each walked node is cross-referenced against Phase 1 LUIDs as a sanity check.

**OPSEC profile:**
A process handle to `lsass.exe` plus repeated `ReadProcessMemory` calls is the highest-fidelity EDR signal in the credential-dumping stack — equivalent to mimikatz/dumpit. Use only when the engagement permits visible LSASS interaction. Phase 1 (`-action insitu`) is the quieter alternative when only session metadata is required.

**Output:**
Header summary plus structured JSON containing the LSASS PID, lsasrv.dll base/size, resolved anchor address, walked-node count, cross-reference results, and the first 32 bytes of each node for downstream analysis. Phase 2C will replace the byte-level cross-reference with structured username/domain/AuthPkg parsing and add NT-hash decryption.

**Signature calibration:**
The `LogonSessionList` signature is calibrated for Windows 10 21H2 — Windows 11 23H2. Older or newer builds may emit `signature not found in lsasrv.dll`; future revisions will add a build-aware signature table.

**Requirements:**
- Administrator privileges (SYSTEM may be required when LSA Protection or Credential Guard is enabled)
- Windows 10 21H2 — Windows 11 23H2 (signature drift on other builds)

### Linux — /etc/shadow Extraction

{{% notice info %}}Linux Only{{% /notice %}}

Reads `/etc/shadow` and `/etc/passwd` to extract password hashes with enriched user context (UID, GID, home directory, shell).

Identifies hash algorithms: yescrypt, SHA-512, SHA-256, bcrypt, MD5, DES.

Skips locked and disabled accounts (`!`, `!!`, `*`).

Reports extracted credentials to the Mythic credential vault automatically.

**Requirements:**
- Root privileges (shadow file is root-readable only)

### macOS — Directory Services Hash Extraction

{{% notice info %}}macOS Only{{% /notice %}}

Reads user plist files from `/var/db/dslocal/nodes/Default/users/` and extracts password hashes using a native binary plist parser (no subprocess).

Parses the `ShadowHashData` attribute, which contains a nested binary plist with the actual hash algorithms:

- **SALTED-SHA512-PBKDF2** (macOS 10.8+) — Most common. Extracted as `$ml$<iterations>$<salt>$<entropy>` (hashcat mode 7100).
- **SRP-RFC5054-4096-SHA512-PBKDF2** (macOS 10.14+) — Secure Remote Password variant.
- **SALTED-SHA512** (macOS 10.7) — Legacy format, extracted as `$LION$<salt><hash>`.

Automatically skips system/daemon accounts (usernames starting with `_`).

Reports extracted credentials to the Mythic credential vault automatically.

**Requirements:**
- Root privileges (plist files are root-readable only)

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | dump | `dump`: extract local NTLM hashes from SAM (Windows SYSTEM required). `insitu`: enumerate active logon sessions via in-process LSA APIs (Windows admin required). `insitu-full`: open lsass.exe with PROCESS_VM_READ, sigscan lsasrv.dll for LogonSessionList, walk the linked list, and cross-reference each node against Phase 1 LUIDs (Windows admin required). `auto-spray`: dump hashes then spray them via cred-check against target hosts. |
| targets | No | (auto) | Target hosts for auto-spray (IPs, comma-separated, or CIDR). If empty, uses active callback hosts. |
| format | No | text | Output format: `text` or `json` (Linux/macOS only) |

## Usage

```
hashdump
hashdump -format json
hashdump -action insitu
hashdump -action insitu-full
hashdump -action auto-spray
hashdump -action auto-spray -targets 192.168.1.0/24,10.0.0.5
```

### Auto-Spray Chain

The `auto-spray` action creates an automated subtask chain:
1. Runs `hashdump` to extract local hashes
2. Parses the output for sprayable credentials (skips machine accounts and empty hashes)
3. Creates parallel `cred-check` subtasks for each credential against target hosts
4. Aggregates results and reports valid/invalid credentials

## Example Output

**Windows:**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
setup:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
```

**Linux:**
```
[*] Dumping /etc/shadow — 2 hashes found

root:$y$j9T$abc123$longhashvalue
  UID=0 GID=0 Home=/root Shell=/bin/bash Type=yescrypt
setup:$6$rounds=5000$salt$hashvalue
  UID=1000 GID=1000 Home=/home/setup Shell=/bin/bash Type=SHA-512
```

## Workflow

**Windows:**
1. Run `getsystem` to get SYSTEM token
2. Run `hashdump`
3. Use hashes for pass-the-hash (`smb`, `winrm`) or crack with hashcat (`-m 1000`)
4. Run `rev2self` to drop SYSTEM privileges

**Linux:**
1. Ensure callback is running as root
2. Run `hashdump`
3. Crack with hashcat (`-m 1800` for SHA-512, `-m 3200` for bcrypt)

**macOS:**
1. Ensure callback is running as root
2. Run `hashdump`
3. Crack PBKDF2 hashes with hashcat (`-m 7100`)

## Example Output (macOS)

```
[*] Dumping macOS Directory Services — 2 hashes found

gary:$ml$50000$0001020304...salt...$8081828384...entropy...
  UID=501 GID=20 Home=/Users/gary Shell=/bin/zsh Type=SALTED-SHA512-PBKDF2
admin:$ml$38000$aabbccdd...salt...$deadbeef...entropy...
  UID=502 GID=20 Home=/Users/admin Shell=/bin/bash Type=SALTED-SHA512-PBKDF2
```

## MITRE ATT&CK Mapping

- T1003.001 — OS Credential Dumping: LSASS Memory (`insitu` action)
- T1003.002 — OS Credential Dumping: Security Account Manager (`dump` action, Windows)
- T1003.008 — OS Credential Dumping: /etc/passwd and /etc/shadow (Linux/macOS)
