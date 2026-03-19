+++
title = "find"
chapter = false
weight = 109
hidden = false
+++

## Summary

Recursively search for files by name pattern (glob) with optional size, date, type, permission, and owner filters. Useful for post-exploitation reconnaissance — locating config files, credentials, SUID binaries, world-writable files, and files owned by specific users.

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
| perm | No | - | Permission filter: `suid`, `sgid`, `writable` (world-writable), `executable`, or octal (e.g., `4000` for SUID, `0002` for world-writable) |
| owner | No | - | Owner filter: username (e.g., `root`) or numeric UID (e.g., `0`) |

*Pattern is required unless at least one filter (size, date, type, perm, or owner) is specified, in which case it defaults to `*`.

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

### Find SUID binaries (privilege escalation)
```
find -path /usr -perm suid -type f
```
Finds all SUID binaries under /usr — critical for privilege escalation enumeration.

### Find world-writable files
```
find -path / -perm writable -type f -max_depth 3
```
Finds world-writable files that could be modified for persistence or exploitation.

### Find files owned by root
```
find -path /tmp -owner root -type f
```
Finds root-owned files in /tmp — potential targets for symlink attacks or race conditions.

### Find executable files owned by a specific user
```
find -path /opt -perm executable -owner www-data
```
Finds executable files owned by web server user — useful for understanding web app deployment.

### Find SGID binaries using octal
```
find -path /usr -perm 2000 -type f
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
