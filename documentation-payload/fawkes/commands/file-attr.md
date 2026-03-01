+++
title = "file-attr"
chapter = false
weight = 216
hidden = false
+++

## Summary

Get or set file system attributes. View current attributes on any file, or modify them to hide files, protect persistence mechanisms, or alter file behavior.

Platform-specific attributes:

| Platform | Available Attributes |
|----------|---------------------|
| Windows | hidden, readonly, system, archive, not_indexed |
| Linux | immutable, append, nodump, noatime, sync, nocow |
| macOS | hidden, immutable, append, sys_immutable, sys_append |

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| path | Yes | | Path to the file to inspect or modify |
| attrs | No | | Comma-separated attribute changes: `+attr` to set, `-attr` to clear. Omit to view current attributes. |

## Usage

View file attributes:
```
file-attr -path C:\temp\payload.exe
```

Hide a file on Windows:
```
file-attr -path C:\temp\payload.exe -attrs "+hidden,+system"
```

Make a persistence file immutable on Linux (requires root):
```
file-attr -path /etc/cron.d/backdoor -attrs "+immutable"
```

Remove immutable flag:
```
file-attr -path /etc/cron.d/backdoor -attrs "-immutable"
```

Hide a file on macOS:
```
file-attr -path /tmp/.hidden_file -attrs "+hidden"
```

Multiple changes at once:
```
file-attr -path /tmp/file -attrs "+nodump,+noatime,-append"
```

## Notes

- Setting `immutable` on Linux/macOS typically requires root privileges.
- Windows `system` attribute marks files as OS files (hidden from Explorer by default).
- Linux attributes use `ioctl` on ext2/3/4, XFS, and btrfs filesystems. Other filesystems may return an error.
- macOS `sys_immutable` and `sys_append` are system-level flags requiring root.

## MITRE ATT&CK Mapping

- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1222** — File and Directory Permissions Modification
