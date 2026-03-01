+++
title = "encrypt"
chapter = false
weight = 204
hidden = false
+++

## Summary

Encrypt or decrypt files using AES-256-GCM (Galois/Counter Mode) for secure data staging before exfiltration. Automatically generates a cryptographically random 256-bit key when encrypting, or accepts a user-provided key. The encrypted output includes a random nonce prepended to the ciphertext with GCM authentication tag for integrity verification.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | encrypt | `encrypt` or `decrypt` |
| path | Yes | | Path to file to encrypt/decrypt |
| output | No | auto | Output file path. Defaults to `<path>.enc` for encrypt, strips `.enc` for decrypt |
| key | No | auto-gen | Base64-encoded AES-256 key. Auto-generated for encrypt, required for decrypt |

## Usage

Encrypt a file (key auto-generated):
```
encrypt -action encrypt -path /tmp/exfil_data.tar.gz
```

Output:
```
Encrypted: /tmp/exfil_data.tar.gz → /tmp/exfil_data.tar.gz.enc
Algorithm: AES-256-GCM
Key (base64): abc123...==
Input size:  1048576 bytes
Output size: 1048604 bytes

⚠ Save the key — it is required for decryption
```

Decrypt with the saved key:
```
encrypt -action decrypt -path /tmp/exfil_data.tar.gz.enc -key abc123...==
```

Encrypt with custom output path:
```
encrypt -action encrypt -path C:\Users\target\Documents\secrets.xlsx -output C:\Users\target\AppData\Local\Temp\staged.dat
```

Encrypt with a pre-shared key:
```
encrypt -action encrypt -path /data/dump.sql -key YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
```

## File Format

The encrypted file format is:
```
[12-byte nonce][ciphertext + 16-byte GCM tag]
```

- **Nonce**: 12 bytes, cryptographically random, unique per encryption
- **Ciphertext**: Same length as plaintext
- **GCM tag**: 16 bytes, provides authentication (detects tampering or wrong key)

## MITRE ATT&CK Mapping

- **T1560.001** — Archive Collected Data: Archive via Utility
