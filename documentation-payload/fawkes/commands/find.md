+++
title = "find"
chapter = false
weight = 109
hidden = false
+++

## Summary

Recursively search for files by name pattern (glob) with optional size, date, and type filters. Useful for post-exploitation reconnaissance — locating config files, credentials, documents, recently modified files, and large data targets.

Cross-platform — works on Windows, Linux, and macOS.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| pattern | No* | * | Glob pattern to match filenames (e.g., `*.txt`, `password*`, `*.kdbx`) |
| path | No | . | Directory to start the search in |
| max_depth | No | 10 | Maximum directory depth to traverse |
| min_size | No | 0 | Minimum file size in bytes (0 = no minimum) |
| max_size | No | 0 | Maximum file size in bytes (0 = no maximum) |
| newer | No | 0 | Only files modified within the last N minutes |
| older | No | 0 | Only files modified more than N minutes ago |
| type | No | - | `f` for files only, `d` for directories only |

*Pattern is required unless at least one filter (size, date, or type) is specified, in which case it defaults to `*`.

## Usage

### Basic file search
```
find -pattern *.conf
find -path C:\Users -pattern *.kdbx
find -path /etc -pattern *.conf -max_depth 3
```

### Find large files for exfiltration targets
```
find -path C:\Users\target -min_size 1048576 -pattern *.xlsx
```
Finds Excel files larger than 1MB.

### Find recently modified files
```
find -path /home/user -newer 60 -type f
```
Files modified in the last 60 minutes (useful for tracking user activity).

### Find old files that haven't been touched
```
find -path /tmp -older 1440 -type f
```
Files not modified in the last 24 hours (1440 minutes).

### Combine filters
```
find -path C:\Users -pattern *.docx -min_size 10240 -newer 120
```
Word documents larger than 10KB modified in the last 2 hours.

### Find directories only
```
find -path /home -type d -pattern .ssh
```

## Example Output
```
Found 3 match(es) for '*.conf' in C:\Users\setup:

12.5 KB      2026-03-01 14:30 C:\Users\setup\AppData\Local\app.conf
1.2 KB       2026-02-28 09:15 C:\Users\setup\.ssh\config.conf
500 B        2026-01-15 11:00 C:\Users\setup\backup.conf
```

Results include file size and modification timestamp. Capped at 500 entries.

## MITRE ATT&CK Mapping

- **T1083** — File and Directory Discovery
