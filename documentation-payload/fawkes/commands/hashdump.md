+++
title = "hashdump"
chapter = false
weight = 105
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Extract local account NTLM password hashes from the SAM (Security Account Manager) database by reading and decrypting the SYSTEM and SAM registry hives in-memory. No files are written to disk.

Output format matches the standard `pwdump` format:
```
username:RID:LM_hash:NT_hash:::
```

### How It Works

1. **Boot Key Extraction** — Reads class names from four LSA subkeys (`JD`, `Skew1`, `GBG`, `Data`) under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` and applies a permutation to derive the 16-byte boot key.
2. **Hashed Boot Key Derivation** — Reads the SAM `F` value from `HKLM\SAM\SAM\Domains\Account` and decrypts it using the boot key. Supports both RC4 (SAM revision 1, pre-Win10) and AES-128-CBC (SAM revision 2, Win10+).
3. **User Enumeration** — Enumerates user RID subkeys under `HKLM\SAM\SAM\Domains\Account\Users` and reads each user's `V` value.
4. **Hash Decryption** — Decrypts each user's NT and LM hashes using the hashed boot key and RID-derived DES keys.

### Requirements

- **Administrator privileges** — High integrity required for SeBackupPrivilege
- Uses `RegCreateKeyExW` with `REG_OPTION_BACKUP_RESTORE` to bypass SAM DACL restrictions
- **SYSTEM token recommended** — Run `getsystem` first for maximum reliability
- No files written to disk — all operations are registry reads

### Arguments

None. The command takes no parameters.

## Usage

```
hashdump
```

## Example Output

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:b20b7632d036ba2dae0705764042a750:::
setup:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
```

The LM hash `aad3b435b51404ee` indicates LM hashing is disabled (default on modern Windows). The NT hash is the NTLM hash that can be used for pass-the-hash or offline cracking.

## Workflow

1. Run `getsystem` to get SYSTEM token (recommended)
2. Run `hashdump`
3. Use hashes for pass-the-hash (`smb`, `winrm`) or crack offline with hashcat (`-m 1000`)
4. Run `rev2self` to drop SYSTEM privileges

## MITRE ATT&CK Mapping

- T1003.002 — OS Credential Dumping: Security Account Manager
