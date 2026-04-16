+++
title = "upload"
chapter = false
weight = 103
hidden = false
+++

## Summary

Upload a file to the target system using chunked file transfer. Supports auto-decompression of gzip files and SHA256 hash verification. Use the modal popup to select the file and specify the destination path.

### Arguments

#### File
Select a file from your computer or a file already uploaded to Mythic.

#### Remote Path (optional)
Full path where the file will be written on the target.

#### Overwrite (optional)
Overwrite the file if it already exists. Default: false.

#### Auto-Decompress (gzip) (optional)
Automatically decompress gzip-compressed files after transfer. Useful for bandwidth-efficient round-trip with compressed downloads. Default: false.

## Usage

Use the Mythic UI popup to select the file and destination path.

### Upload with auto-decompression
When uploading a `.gz` file that was previously downloaded with compression enabled, use the decompress option to automatically decompress after transfer:

1. Download with compression: `download /var/log/syslog` (creates `syslog.gz`)
2. Upload back with decompression: Set "Auto-Decompress (gzip)" to true

## Integrity Verification

All file transfers include SHA256 hash computation:
- **Normal upload:** SHA256 of the transferred data
- **Decompressed upload:** SHA256 of the decompressed file content

## MITRE ATT&CK Mapping

- **T1020** — Automated Exfiltration
- **T1030** — Data Transfer Size Limits
- **T1041** — Exfiltration Over C2 Channel
- **T1105** — Ingress Tool Transfer
