+++
title = "secure-delete"
chapter = false
weight = 172
hidden = false
+++

## Summary

Securely delete files by overwriting their contents with cryptographically random data before removing them from disk. Prevents forensic recovery of deleted file contents. Supports single files and recursive directory deletion.

{{% notice info %}}Cross-platform — works on Windows, Linux, and macOS{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| path | Yes | | Path to file or directory to securely delete |
| passes | No | 3 | Number of random data overwrite passes before removal |

## Usage

Securely delete a single file (default 3 passes):
```
secure-delete -path /tmp/payload.bin
```

Delete with extra passes for high-security cleanup:
```
secure-delete -path C:\Users\setup\tool.exe -passes 7
```

Recursively secure-delete an entire directory:
```
secure-delete -path /tmp/artifacts
```

## MITRE ATT&CK Mapping

- **T1070.004** — Indicator Removal: File Deletion
- **T1485** — Data Destruction
