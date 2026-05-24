+++
title = "upload"
chapter = false
weight = 103
hidden = false
+++

## Summary

Upload a file to the target system using chunked file transfer. Supports on-disk encoding (XOR/AES) for AV evasion, auto-decompression of gzip files, and SHA256 hash verification. Use the modal popup to select the file and specify the destination path.

### Arguments

#### File
Select a file from your computer or a file already uploaded to Mythic.

#### Remote Path (optional)
Full path where the file will be written on the target.

#### Overwrite (optional)
Overwrite the file if it already exists. Default: false.

#### Auto-Decompress (gzip) (optional)
Automatically decompress gzip-compressed files after transfer. Useful for bandwidth-efficient round-trip with compressed downloads. Default: false.

#### Encode on Disk (optional)
Encode the file before writing to disk using XOR or AES-256-CTR. Prevents static AV/EDR detection of file contents. A random key is generated and returned in the output — use it with `execute-shellcode -encoding <method> -key <hex>` to decode at runtime. Options: `xor`, `aes`. Default: none.

## Usage

Use the Mythic UI popup to select the file and destination path.

### Upload with auto-decompression
When uploading a `.gz` file that was previously downloaded with compression enabled, use the decompress option to automatically decompress after transfer:

1. Download with compression: `download /var/log/syslog` (creates `syslog.gz`)
2. Upload back with decompression: Set "Auto-Decompress (gzip)" to true

### Upload with encoding
When uploading a tool or payload that should not be detectable by static AV scanning on disk:

1. Upload with encoding: Set "Encode on Disk" to `xor` or `aes`
2. The output includes the hex-encoded key
3. To execute: use `execute-shellcode` with the matching `-encoding` and `-key` parameters

## Integrity Verification

All file transfers include SHA256 hash computation:
- **Normal upload:** SHA256 of the transferred data
- **Decompressed upload:** SHA256 of the decompressed file content

## MITRE ATT&CK Mapping

- **T1020** — Automated Exfiltration
- **T1030** — Data Transfer Size Limits
- **T1041** — Exfiltration Over C2 Channel
- **T1105** — Ingress Tool Transfer
- **T1027** — Obfuscated Files or Information
