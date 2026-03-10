+++
title = "timestomp"
chapter = false
weight = 146
hidden = false
+++

## Summary

Modify file timestamps to blend in with surrounding files. Supports reading timestamps, copying timestamps from a reference file, setting specific timestamps, matching directory neighbors, and randomizing within a date range.

On Windows, all three timestamps are modified: access time, modification time, and creation time. On Linux/macOS, access and modification times are modified (creation time is not a standard concept on most Unix filesystems).

This is a critical opsec technique for red team operations — uploaded tools and generated files will have current timestamps that stand out during forensic analysis.

## Arguments

| Argument  | Required | Default | Description |
|-----------|----------|---------|-------------|
| action    | Yes      | get     | `get` to read timestamps, `copy` to copy from another file, `set` to set a specific time, `match` to blend with directory, `random` for random time in range |
| target    | Yes      | -       | Target file to read/modify timestamps on |
| source    | No       | -       | Source file for `copy` action, or range start date for `random` action |
| timestamp | No       | -       | Timestamp for `set` action, or range end date for `random` action |

### Supported Timestamp Formats (for `set` and `random` actions)
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

### Match directory neighbors
Analyzes all files in the same directory and sets the target's timestamps to a random time within the interquartile range (Q1-Q3) of sibling file timestamps. This avoids both the newest and oldest timestamps, making the file blend in naturally.
```
timestomp -action match -target C:\Users\setup\payload.exe
```

### Random timestamp in range
Sets timestamps to a cryptographically random time between two dates.
```
timestomp -action random -target C:\Users\setup\payload.exe -source "2023-01-01" -timestamp "2024-06-15"
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

### Example Output (Match)
```
Matched timestamps on C:\Users\setup\payload.exe to blend with directory
  Directory:    C:\Users\setup (42 sibling files)
  Range (IQR):  2023-08-15T10:30:00Z — 2024-02-20T14:15:00Z
  Set to:       2023-11-03T08:22:41Z
```

### Example Output (Random)
```
Set timestamps on C:\Users\setup\payload.exe to random time: 2023-09-14T16:42:33Z (range: 2023-01-01T00:00:00Z — 2024-06-15T00:00:00Z)
```

## MITRE ATT&CK Mapping

- T1070.006 -- Indicator Removal: Timestomp
