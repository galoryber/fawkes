+++
title = "df"
chapter = false
weight = 116
hidden = false
+++

## Summary

Report filesystem disk space usage. Shows total size, used space, available space, and utilization percentage for each mounted filesystem. Useful for identifying storage constraints, finding large volumes for staging, and understanding disk layout on target systems.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| filesystem | No | — | Filter by device name (substring match) |
| mount_point | No | — | Filter by mount point path (substring match) |
| fstype | No | — | Filter by filesystem type (case-insensitive, e.g. 'ext4', 'ntfs') |

## Usage

```
# Show all filesystems
df

# Filter by device
df -filesystem /dev/sda

# Filter by mount point
df -mount_point /home

# Filter by filesystem type
df -fstype ext4

# Combine filters
df -fstype ntfs -filesystem C:
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
