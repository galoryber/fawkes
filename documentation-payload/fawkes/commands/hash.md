+++
title = "hash"
chapter = false
weight = 155
hidden = false
+++

## Summary

Compute file hashes (MD5, SHA-1, SHA-256, SHA-512) for single files or directories. Supports glob pattern filtering, recursive directory traversal, and configurable file count limits.

Cross-platform — works from Windows, Linux, and macOS agents.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| path | Yes | Path to a file or directory to hash |
| algorithm | No | Hash algorithm: `md5`, `sha1`, `sha256`, `sha512` (default: `sha256`) |
| recursive | No | Recurse into subdirectories when hashing a directory (default: `false`) |
| pattern | No | Glob pattern to filter files (e.g., `*.exe`, `*.dll`) |
| max_files | No | Maximum number of files to hash (default: 500) |

## Usage

### Hash a single file
```
hash -path C:\Windows\System32\notepad.exe
```

### Hash with a specific algorithm
```
hash -path /etc/passwd -algorithm sha512
```

### Hash directory with pattern filter
```
hash -path C:\Windows\System32 -algorithm md5 -pattern *.ini
```

### Recursive directory hash
```
hash -path /var/log -algorithm sha1 -recursive true -pattern *.log -max_files 50
```

## Output

```
[*] SHA256 hashes (1 files):
------------------------------------------------------------
84b484fd3636f2ca3e468d2821d97aacde8a143a2724a3ae65f48a33ca2fd258  C:\Windows\System32\notepad.exe  (352.0 KB)
------------------------------------------------------------
[*] 1 files hashed
```

### Directory output
```
[*] MD5 hashes (2 files):
------------------------------------------------------------
3b622cd491fb80f624a5039ae24f4b54  C:\Windows\System32\WimBootCompress.ini  (2.4 KB)
d602ca245cc6774a0981b607f0675609  C:\Windows\System32\tcpmon.ini  (58.7 KB)
------------------------------------------------------------
[*] 2 files hashed
```

## OPSEC Considerations

- **File I/O**: Reads file contents to compute hashes — may trigger file access monitoring or EDR telemetry
- **Directory scanning**: Large directory scans with `recursive` enabled can generate significant I/O. Use `max_files` to limit scope
- **No subprocess**: Hashing is performed in-process using Go's crypto libraries — no external tools are spawned

## MITRE ATT&CK Mapping

- T1083 — File and Directory Discovery
