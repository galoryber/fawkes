+++
title = "timestomp"
chapter = false
weight = 146
hidden = false
+++

## Summary

Modify file timestamps to blend in with surrounding files. Supports reading timestamps, copying timestamps from a reference file, and setting specific timestamps.

On Windows, all three timestamps are modified: access time, modification time, and creation time. On Linux/macOS, access and modification times are modified (creation time is not a standard concept on most Unix filesystems).

This is a critical opsec technique for red team operations — uploaded tools and generated files will have current timestamps that stand out during forensic analysis.

## Arguments

| Argument  | Required | Default | Description |
|-----------|----------|---------|-------------|
| action    | Yes      | get     | `get` to read timestamps, `copy` to copy from another file, `set` to set a specific time |
| target    | Yes      | -       | Target file to read/modify timestamps on |
| source    | No       | -       | Source file to copy timestamps from (only used with `copy` action) |
| timestamp | No       | -       | Timestamp string (only used with `set` action) |

### Supported Timestamp Formats (for `set` action)
- `2024-01-15T10:30:00Z` (RFC3339)
- `2024-01-15T10:30:00` (ISO without timezone)
- `2024-01-15 10:30:00`
- `2024-01-15`
- `01/15/2024 10:30:00`
- `01/15/2024`

## Usage

### Get timestamps
```
timestomp -action get -target C:\Users\setup\payload.exe
```

### Copy timestamps from another file
```
timestomp -action copy -target C:\Users\setup\payload.exe -source C:\Windows\System32\notepad.exe
```

### Set specific timestamp
```
timestomp -action set -target C:\Users\setup\payload.exe -timestamp "2023-06-15T10:30:00Z"
```

### Example Output (Get)
```
Timestamps for: C:\Windows\System32\notepad.exe
  Modified:  2024-01-12T23:00:37-06:00
  Accessed:  2024-02-12T03:06:23-06:00
  Created:   2024-01-12T23:00:37-06:00
```

### Example Output (Copy)
```
Copied timestamps from C:\Windows\System32\notepad.exe to C:\Users\setup\payload.exe
  Source modified:  2024-01-12T23:00:37-06:00
  Source accessed:  2024-02-12T03:06:23-06:00
```

### Example Output (Set)
```
Set all timestamps on C:\Users\setup\payload.exe to 2023-06-15T10:30:00Z
```

## MITRE ATT&CK Mapping

- T1070.006 -- Indicator Removal: Timestomp
