+++
title = "chown"
chapter = false
weight = 115
hidden = false
+++

## Summary

Change file and directory ownership on Linux and macOS. Supports specifying the owner by username or numeric UID, and optionally the group by name or GID. Recursive directory operations are supported.

{{% notice info %}}Linux/macOS Only{{% /notice %}}

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| path | Yes | Path to file or directory |
| owner | No* | New owner — username or numeric UID (*at least one of owner or group required) |
| group | No* | New group — group name or numeric GID (*at least one of owner or group required) |
| recursive | No | Apply ownership recursively to directory contents (default: `false`) |

## Usage

### Change owner by username
```
chown -path /tmp/payload -owner root
```

### Change owner and group
```
chown -path /var/data -owner www-data -group www-data
```

### Change by numeric UID/GID
```
chown -path /tmp/file -owner 1000 -group 1000
```

### Recursive directory ownership
```
chown -path /opt/app -owner appuser -group appgroup -recursive true
```

### Change group only
```
chown -path /tmp/shared -group developers
```

## Output

```
[+] /tmp/payload
    Owner: root (uid=0)
```

### With owner and group
```
[+] /var/data
    Owner: www-data (uid=33), www-data (gid=33)
```

### Recursive output
```
[*] 12 items changed to appuser (uid=1001), appgroup (gid=1001)
```

## OPSEC Considerations

- **Requires privileges**: Changing ownership to another user typically requires root. Changing to yourself or your own group is always allowed
- **File metadata changes**: Ownership changes update file metadata (ctime) which may be logged
- **No subprocess**: Uses Go's `os.Chown` — no external commands spawned

## MITRE ATT&CK Mapping

- T1222 — File and Directory Permissions Modification
