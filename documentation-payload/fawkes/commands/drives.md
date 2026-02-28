+++
title = "drives"
chapter = false
weight = 112
hidden = false
+++

## Summary

List all available drives/volumes and mounted filesystems on the system. Cross-platform.

On **Windows**, uses GetLogicalDrives/GetDriveTypeW/GetDiskFreeSpaceExW to enumerate drive letters with type (Fixed, Removable, Network, CD-ROM), volume label, and disk space.

On **Linux**, reads `/proc/mounts` and uses `statfs` for disk space. Filters pseudo-filesystems (proc, sysfs, cgroup, etc.).

On **macOS**, parses `mount` command output and uses `statfs` for disk space.

## Arguments

None.

## Usage

```
drives
```

### Browser Script

Output is rendered as a sortable table in the Mythic UI with columns: Drive, Type, Label, Free (GB), Total (GB), Used %. Volumes over 90% usage are highlighted red, over 75% in orange.

### Example Output (JSON)
```json
[
  {"drive":"C:\\","type":"Fixed","label":"","free_gb":26.6,"total_gb":79.1},
  {"drive":"D:\\","type":"Network","label":"FileShare","free_gb":50.2,"total_gb":100.0}
]
```

## MITRE ATT&CK Mapping

- T1083 -- File and Directory Discovery
