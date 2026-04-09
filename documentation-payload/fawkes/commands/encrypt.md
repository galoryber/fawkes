+++
title = "encrypt"
chapter = false
weight = 204
hidden = false
+++

## Summary

Encrypt or decrypt files using AES-256-GCM (Galois/Counter Mode). Supports single file operations and batch operations for ransomware simulation (T1486) and recovery. Batch encryption adds `.fawkes` extension and outputs a recovery key. Safety gates prevent accidental destructive operations.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | encrypt | `encrypt`, `decrypt`, `encrypt-files` (batch T1486), `decrypt-files` (batch recovery) |
| path | Yes | | File path, glob pattern (encrypt-files), or directory (decrypt-files) |
| output | No | auto | Output file path (single file mode only) |
| key | No | auto-gen | Base64-encoded AES-256 key. Auto-generated for encrypt, required for decrypt |
| confirm | No | | Safety gate: `SIMULATE` for encrypt-files |
| max_files | No | 100 | Maximum files to encrypt in batch mode |

## Usage

Encrypt a single file:
```
encrypt -action encrypt -path /tmp/exfil_data.tar.gz
```

Decrypt with saved key:
```
encrypt -action decrypt -path /tmp/exfil_data.tar.gz.enc -key abc123...==
```

### Ransomware Simulation (T1486)

Batch encrypt files by glob pattern:
```
encrypt -action encrypt-files -path '/home/user/Documents/*.docx' -confirm SIMULATE
```

Output:
```
=== Ransomware Simulation (T1486) ===
Pattern: /home/user/Documents/*.docx
Files encrypted: 15/15
Total bytes: 2458624
Extension: .fawkes
Algorithm: AES-256-GCM
Recovery Key (base64): abc123...==

⚠ SAVE THE RECOVERY KEY — required for decrypt-files
```

Recover encrypted files:
```
encrypt -action decrypt-files -path /home/user/Documents -key abc123...==
```

{{% notice warning %}}
encrypt-files is a destructive operation — original files are deleted after encryption. Always save the recovery key. Requires `-confirm SIMULATE` safety gate.
{{% /notice %}}

## File Format

Encrypted files use: `[12-byte nonce][ciphertext + 16-byte GCM tag]`

Batch encrypted files get `.fawkes` extension. All files in a batch share the same AES-256 key.

## MITRE ATT&CK Mapping

- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1486** — Data Encrypted for Impact (encrypt-files action)
