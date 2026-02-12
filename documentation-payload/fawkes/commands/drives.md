+++
title = "drives"
chapter = false
weight = 112
hidden = false
+++

{{% notice info %}}Windows Only{{% /notice %}}

## Summary

List all available drives/volumes on the system, including drive type (Fixed, Removable, Network, CD-ROM), volume label, and disk space information (free and total in GB).

Useful for identifying mapped network drives, removable media, and available storage during an engagement.

## Arguments

None.

## Usage

```
drives
```

### Example Output
```
Drive  Type         Label                      Free (GB)      Total (GB)
------------------------------------------------------------------------
C:\    Fixed                                        26.6            79.1
D:\    Network      FileShare                       50.2           100.0
E:\    CD-ROM       virtio-win-0.1.285               0.0             0.7

[3 drives found]
```

## MITRE ATT&CK Mapping

- T1083 -- File and Directory Discovery
