+++
title = "touch"
chapter = false
weight = 185
hidden = false
+++

## Summary

Create an empty file or update an existing file's access and modification timestamps to the current time. Optionally creates parent directories. No subprocess spawned.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| path | Yes | Path to file to create or update |
| mkdir | No | Create parent directories if they don't exist (default: `false`) |

## Usage

### Create a new empty file
```
touch -path /tmp/marker.txt
```

### Update timestamps on existing file
```
touch -path /var/log/app.log
```

### Create with nested directories
```
touch -path /opt/app/config/settings.conf -mkdir true
```

## Output

### New file
```
[+] Created /tmp/marker.txt
```

### Existing file
```
[+] Updated timestamps on /var/log/app.log
```

## OPSEC Considerations

- **No subprocess**: Uses Go's `os.Create` and `os.Chtimes` — no external commands spawned
- **File creation**: New files are created with 0644 permissions
- **Timestamp update**: Modifies both access and modification times to current time
- **Metadata change**: Updating timestamps changes file metadata (ctime), which may be logged

## MITRE ATT&CK Mapping

- T1106 — Native API
