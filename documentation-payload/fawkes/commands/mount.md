+++
title = "mount"
chapter = false
weight = 140
hidden = false
+++

## Summary

List mounted filesystems with device, mount point, filesystem type, and mount options. Useful for discovering network shares, encrypted volumes, removable media, and understanding filesystem layout on target systems.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `-filter` | No | (none) | Case-insensitive substring filter on device or mount point |
| `-fstype` | No | (none) | Filter by filesystem type (e.g., ext4, nfs, tmpfs, ntfs) |

## Usage

List all mounts:
```
mount
```

Filter by mount point or device name:
```
mount -filter home
```

Show only NFS mounts:
```
mount -fstype nfs
```

## MITRE ATT&CK Mapping

- **T1082** — System Information Discovery
