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

In-situ LSASS analysis: opens `lsass.exe` with `PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION`, locates `lsasrv.dll` in the loader list, pattern-scans the mapped image for the mimikatz `LogonSessionList` signature, decodes the RIP-relative `MOV r8,[mem]` displacement, walks the doubly-linked `LogonSessionList`, and overlays the `KIWI_MSV1_0_LIST_63` struct layout on each walked node to extract the LUID, UserName, Domain, AuthPackage, LogonType, LogonServer, and Credentials list pointer. The structured LUID is the primary cross-reference oracle against Phase 1; a byte-scan fallback flags nodes whose structured LUID is zero so layout drift is visible rather than silent.

For every node with a non-zero `credentials_ptr`, the agent walks the per-AuthPackage credential chain (`KIWI_MSV1_0_CREDENTIAL_LIST`: Flink + AuthenticationPackageId + PrimaryCredentials_data) and dereferences each `KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC` envelope to capture UserName, Domain, and the encrypted credential blob (`encryptedCredentials.Buffer` ciphertext). The ciphertext is reported as a hex preview alongside its LSASS-virtual address and length.

In addition (Phase 2C-ii-b), the agent pattern-scans the same `lsasrv.dll` image for `LsaInitializeProtectedMemory_Internal`, resolves three RIP-relative MOV instructions to recover the LSASS-virtual addresses of the IV, `h3DesKey`, and `hAesKey` globals, and walks the BCrypt key chain (`KIWI_BCRYPT_HANDLE_KEY` → `KIWI_BCRYPT_KEY81` → `KIWI_HARD_KEY`) to extract the raw 16-byte IV plus the 24-byte 3DES and 32-byte AES key bytes. Both BCrypt tag values (`UUUR` on the handle, `MSSK` on the inner key blob) are validated and reported in the JSON for layout-drift diagnostics.

Phase 2C-ii-c then uses the captured key material to decrypt every ciphertext blob captured by Phase 2C-ii-a and overlays the `KIWI_MSV1_0_PRIMARY_CREDENTIAL_10_NEW` layout to extract NT/LM/SHA hashes plus the four BOOLEAN validity flags (`isIso`, `isNtOwfPassword`, `isLmOwfPassword`, `isShaOwPassword`). Cipher selection mirrors `lsasrv!LsaProtectMemory` exactly: `len(ciphertext) % 8 != 0` selects AES-256-CFB with the full 16-byte IV; otherwise 3DES-CBC with the first 8 bytes of the stored IV. Decryption runs in-process via Go stdlib `crypto/aes` and `crypto/des` — no `BCryptDecrypt` call (and no extra LSASS handle) is required. For every recovered MSV1_0 credential with a non-zero NT hash, the agent emits a `username:rid:lm:nt:::` line at the top of the human-readable output; the existing `dump`-action ProcessResponse hook walks those lines and registers each hash in the Mythic credential vault, so MSV1_0 walk hashes flow into the same store as SAM-dump hashes.

**OPSEC profile:**
A process handle to `lsass.exe` plus repeated `ReadProcessMemory` calls (the lsasrv.dll image read, every walked LogonSessionList node, every `LSA_UNICODE_STRING.Buffer` dereference for username/domain/auth-package strings, every `KIWI_MSV1_0_CREDENTIAL_LIST` entry, every `KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC` envelope reachable from `credentials_ptr`, and the IV global + `KIWI_BCRYPT_HANDLE_KEY`/`KIWI_BCRYPT_KEY81`/`KIWI_HARD_KEY` chain reachable from `LsaInitializeProtectedMemory_Internal`) is the highest-fidelity EDR signal in the credential-dumping stack — equivalent to mimikatz/dumpit. Decryption itself is the operationally-loud step: NT hashes will appear in operator output and propagate into the credential vault. Use only when the engagement permits visible LSASS interaction. Phase 1 (`-action insitu`) is the quieter alternative when only session metadata is required.

**Output:**
A leading `username:rid:lm:nt:::` text block (one line per recovered MSV1_0 credential) followed by a header summary and structured JSON containing the LSASS PID, lsasrv.dll base/size, resolved anchor address, struct-layout label, crypto-layout label, primary-credential-layout label, walked-node count, structured-parse count, cross-reference results, credential-walk counts, decrypted-blob counts, hash-extraction counts, a top-level `lsa_crypto` block (IV address + bytes, h3DesKey + hAesKey blobs with handle/key tags + raw key bytes), and per-node fields: parsed LUID, username, domain, auth package, logon type, logon server, credentials-list pointer, a 32-byte raw preview, and a `credentials` array of `{ auth_package, parsed_username, parsed_domain, encrypted_address, encrypted_length, encrypted_hex_preview, decrypted: { algorithm, plaintext_length, layout, is_iso, is_nt_owf_password, is_lm_owf_password, is_sha_owf_password, nt_hash_hex, lm_hash_hex, sha_hash_hex, dump_line } }` per AuthPackage entry. Non-MSV1_0 entries (Kerberos, WDigest, CloudAP) populate the `decrypted` block but typically have all-zero NT/LM/SHA fields — those entries are skipped during dump-line emission to avoid spurious credential-vault registrations.

**Signature & layout calibration:**
The `LogonSessionList` signature, `KIWI_MSV1_0_LIST_63` field offsets, `KIWI_MSV1_0_CREDENTIAL_LIST` / `KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC` envelope layouts, `LsaInitializeProtectedMemory_Internal` signature + `{IV: +9, h3DesKey: -64, hAesKey: -75}` MOV-start offsets, and `KIWI_MSV1_0_PRIMARY_CREDENTIAL_10_NEW` field offsets (`{NtOwf: 0x4A, LmOwf: 0x5A, ShaOwf: 0x6A, fixed=0x7E}`) are calibrated for Windows 10 21H2 — Windows 11 23H2 (mimikatz `signature_x64_w8` + `_10_1607` plaintext layout). Older or newer builds may emit `signature not found in lsasrv.dll` (signature miss), report many walked nodes with empty `parsed_username`/`parsed_domain` and zero `parsed_luid` (LogonSessionList layout drift), emit `credential_walk_err` lines / empty `parsed_username` inside the `credentials` array (CREDENTIAL_LIST layout drift), report `lsa_crypto.h3deskey.handle_tag_valid: false` / `key_tag_valid: false` (BCrypt key layout drift), or surface `decrypted` blocks with all-zero hashes despite valid tags (PRIMARY_CREDENTIAL_10 layout drift; the layout offsets need updating for `_10_OLD` 1507..1510 / `_10` 1511..1606 / `_26100` 24H2+). When that happens, the byte-scan fallback still flags nodes whose raw bytes contain a Phase 1 LUID, so the walk-soundness check is preserved even if a field overlay is wrong.

**Requirements:**
- Administrator privileges (SYSTEM may be required when LSA Protection or Credential Guard is enabled)
- Windows 10 21H2 — Windows 11 23H2 (signature/layout drift on other builds)

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
| action | No | dump | `dump`: extract local NTLM hashes from SAM (Windows SYSTEM required). `insitu`: enumerate active logon sessions via in-process LSA APIs (Windows admin required). `insitu-full`: open lsass.exe with PROCESS_VM_READ, sigscan lsasrv.dll for LogonSessionList, walk the linked list, parse each node's KIWI_MSV1_0_LIST_63 fields, walk the per-AuthPackage credential chain at credentials_ptr to capture each KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC envelope, sigscan LsaInitializeProtectedMemory_Internal to recover the IV / h3DesKey / hAesKey BCrypt key globals + raw 16-byte IV / 24-byte 3DES / 32-byte AES key bytes, AES-256-CFB / 3DES-CBC decrypt every captured ciphertext blob (selected per-blob by `len % 8`), and overlay the KIWI_MSV1_0_PRIMARY_CREDENTIAL_10_NEW layout to extract NT/LM/SHA hashes — emitted in `username:rid:lm:nt:::` format compatible with the dump-action ProcessResponse credential-vault hook (Phase 2B + 2C-i + 2C-ii-a + 2C-ii-b + 2C-ii-c, Windows admin required). `auto-spray`: dump hashes then spray them via cred-check against target hosts. |
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
