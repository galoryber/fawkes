+++
title = "df"
chapter = false
weight = 116
hidden = false
+++

## Summary

Report filesystem disk space usage. Shows total size, used space, available space, and utilization percentage for each mounted filesystem. Useful for identifying storage constraints, finding large volumes for staging, and understanding disk layout on target systems.

## Arguments

No arguments required. Reports all mounted filesystems.

## Usage

Show disk space:
```
df
```

## Output Format

Returns a JSON array rendered as a sortable table via browser script:
```json
[
  {
    "filesystem": "/dev/sda1",
    "fstype": "ext4",
    "mount_point": "/",
    "total_bytes": 53660876800,
    "used_bytes": 21474836480,
    "avail_bytes": 29498040320,
    "use_percent": 42
  }
]
```

The browser script formats byte values as human-readable sizes and highlights volumes at >=90% usage (red) and >=75% usage (orange).

## MITRE ATT&CK Mapping

- **T1082** — System Information Discovery
