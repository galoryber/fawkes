+++
title = "write-file"
chapter = false
weight = 195
hidden = false
+++

## Summary

Write text or base64-decoded binary content to a file on the target, or deface web server pages. Two modes:

- **write** (default): Create, overwrite, or append content to files
- **deface**: Replace web content with a defacement message (T1491 Defacement)

No subprocess spawned. Creates parent directories on request.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | No | `write` (default) or `deface` (web defacement T1491) |
| path | Yes | Path to write to |
| content | Yes* | Text content to write (*optional for deface — uses default HTML if empty) |
| base64 | No | Decode content from base64 before writing (default: `false`) |
| append | No | Append to file instead of overwriting (default: `false`) |
| mkdir | No | Create parent directories if they don't exist (default: `false`) |
| confirm | No | Safety gate: `DEFACE` required for deface action |

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

### Deface a web page (T1491)
```
write-file -action deface -path /var/www/html/index.html -confirm DEFACE
```

### Deface with custom message
```
write-file -action deface -path /var/www/html/index.html -content "<h1>Hacked by Red Team</h1>" -confirm DEFACE
```

{{% notice warning %}}
Defacement is a high-visibility impact operation. The modified page is immediately visible to users. Requires `-confirm DEFACE` safety gate. Only use in authorized purple team exercises.
{{% /notice %}}

## OPSEC Considerations

- **No subprocess**: Uses Go's `os.OpenFile` — no shell commands spawned
- **File creation**: Creates files with 0644 permissions by default
- **Disk write**: Content is written to disk and may be detected by file monitoring
- **Directory creation**: Uses 0755 permissions for new directories
- **Defacement**: Immediately visible. FIM/HIDS and web monitoring will detect the change

## MITRE ATT&CK Mapping

- T1105 — Ingress Tool Transfer
- T1059 — Command and Scripting Interpreter
- T1491 — Defacement (deface action)
