+++
title = "write-file"
chapter = false
weight = 195
hidden = false
+++

## Summary

Write text or base64-decoded binary content to a file on the target. Supports creating new files, overwriting existing files, and appending. Creates parent directories on request. No subprocess spawned.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| path | Yes | Path to write to |
| content | Yes | Text content to write (or base64-encoded data if `-base64 true`) |
| base64 | No | Decode content from base64 before writing (default: `false`) |
| append | No | Append to file instead of overwriting (default: `false`) |
| mkdir | No | Create parent directories if they don't exist (default: `false`) |

## Usage

### Write a script
```
write-file -path /tmp/script.sh -content "#!/bin/bash\necho 'hello world'"
```

### Write binary data (base64)
```
write-file -path /tmp/payload.bin -content "SGVsbG8gV29ybGQ=" -base64 true
```

### Append to a file
```
write-file -path /var/log/app.log -content "new log entry\n" -append true
```

### Create nested directories
```
write-file -path /opt/app/config/settings.json -content '{"key":"value"}' -mkdir true
```

### Write a Windows batch script
```
write-file -path C:\Temp\run.bat -content "@echo off\nnet user /domain" -mkdir true
```

## Output

```
[+] Wrote 42 bytes to /tmp/script.sh
```

### Append mode
```
[+] Appended 15 bytes to /var/log/app.log
```

## OPSEC Considerations

- **No subprocess**: Uses Go's `os.OpenFile` — no shell commands spawned
- **File creation**: Creates files with 0644 permissions by default
- **Disk write**: Content is written to disk and may be detected by file monitoring
- **Directory creation**: Uses 0755 permissions for new directories

## MITRE ATT&CK Mapping

- T1105 — Ingress Tool Transfer
- T1059 — Command and Scripting Interpreter
