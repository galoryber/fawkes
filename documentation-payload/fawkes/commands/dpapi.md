+++
title = "dpapi"
chapter = false
weight = 193
hidden = false
+++

## Summary

Provides DPAPI (Data Protection API) blob decryption, master key enumeration, and browser encryption key extraction. Uses Windows CryptUnprotectData for decryption in the current user context.

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | decrypt | `decrypt`, `masterkeys`, or `chrome-key` |
| blob | For decrypt | | Base64-encoded DPAPI blob to decrypt |
| entropy | No | | Optional additional entropy (base64-encoded) |
| path | No | | Custom path for master key search |

## Usage

### Decrypt a DPAPI Blob
```
dpapi -action decrypt -blob <base64_encoded_blob>
```

### List DPAPI Master Keys
```
dpapi -action masterkeys
```

### Extract Chrome/Edge Encryption Key
```
dpapi -action chrome-key
```

## Actions

### decrypt
Decrypts a base64-encoded DPAPI blob using `CryptUnprotectData`. Requires the same user context that encrypted the data. Supports optional entropy parameter for blobs encrypted with additional entropy.

### masterkeys
Enumerates DPAPI master key files across user profiles and system directories. Lists key GUIDs, sizes, and modification times. Useful for identifying which master keys are available for offline decryption.

### chrome-key
Extracts the AES encryption key from Chrome/Edge `Local State` file. The key is protected by DPAPI — this action decrypts it and returns the raw key. Can be used with external tools to decrypt browser databases.

## MITRE ATT&CK Mapping

- **T1555.003** — Credentials from Web Browsers
- **T1555.005** — Password Managers
