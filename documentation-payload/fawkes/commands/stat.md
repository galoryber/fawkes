+++
title = "stat"
chapter = false
weight = 175
hidden = false
+++

## Summary

Display detailed file or directory metadata including type, size, permissions, timestamps, and platform-specific information. Uses `os.Lstat` to report on symlinks themselves rather than following them.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| path | Yes | Path to the file, directory, or symlink to inspect |

## Usage

### Stat a regular file
```
stat -path /etc/passwd
```

### Stat a directory
```
stat -path /tmp
```

### Stat a symlink
```
stat -path /usr/bin/python3
```

### Stat a Windows file
```
stat -path C:\Windows\System32\notepad.exe
```

## Output

### Linux/macOS
```
File:   /etc/passwd
Type:   regular file
Size:   2847 bytes (2.8 KB)
Mode:   -rw-r--r-- (0644)
Modify: 2025-01-15 10:30:22 UTC
Owner:  root (uid=0), root (gid=0)
Inode:  1234567
Links:  1
Access: 2025-01-20 08:15:00 UTC
Change: 2025-01-15 10:30:22 UTC
```

### macOS (additional)
```
Birth:  2024-06-01 12:00:00 UTC
```

### Windows
```
File:   C:\Windows\System32\notepad.exe
Type:   regular file
Size:   201216 bytes (196.5 KB)
Mode:   -rw-rw-rw- (0666)
Modify: 2024-12-10 14:22:15 UTC
Attributes: Archive
Created: 2024-06-15 09:00:00 UTC
Access:  2025-01-20 08:15:00 UTC
```

### Symlink
```
File:   /usr/bin/python3
Type:   symbolic link
Link:   /usr/bin/python3.11
Size:   18 bytes (18 B)
Mode:   Lrwxrwxrwx (0777)
Modify: 2024-11-01 12:00:00 UTC
```

## OPSEC Considerations

- **No subprocess**: Uses Go's `os.Lstat` and platform syscalls — no external commands spawned
- **Read-only**: Does not modify any file metadata (no atime update from this command)
- **Symlink-safe**: Reports symlink metadata without following to the target

## MITRE ATT&CK Mapping

- T1083 — File and Directory Discovery
