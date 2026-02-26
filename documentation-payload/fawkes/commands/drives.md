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

### Example Output (Windows)
```
Drive  Type         Label                      Free (GB)      Total (GB)
------------------------------------------------------------------------
C:\    Fixed                                        26.6            79.1
D:\    Network      FileShare                       50.2           100.0

[2 drives found]
```

### Example Output (Linux)
```
Mount Point                    Device          Type        Free (GB)   Total (GB)  Use%
------------------------------------------------------------------------------------------
/                              /dev/sda1       ext4             18.2         30.0   39%
/home                          /dev/sda2       ext4            120.5        200.0   40%
/boot/efi                      /dev/sda15      vfat              0.5          0.5    5%

[3 filesystems]
```

## MITRE ATT&CK Mapping

- T1083 -- File and Directory Discovery
