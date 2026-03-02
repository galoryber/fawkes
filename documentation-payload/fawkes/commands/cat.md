+++
title = "cat"
chapter = false
weight = 103
hidden = false
+++

## Summary

Display file contents with optional line range, numbering, and size protection. Files larger than 5MB are blocked by default to prevent agent memory issues — use `tail` for large files or override with `-max`.

Cross-platform (Windows, Linux, macOS).

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| path | Yes | - | Full path to the file to read |
| start | No | 0 | Starting line number (1-based) |
| end | No | 0 | Ending line number (0 = end of file) |
| number | No | false | Show line numbers |
| max | No | 5120 | Maximum output size in KB (default 5MB) |

## Usage

### Read a file (backward compatible)
```
cat /etc/passwd
cat C:\Users\admin\Desktop\notes.txt
```

### Read specific line range
```
cat -path /var/log/auth.log -start 100 -end 150
```

### Read from a specific line to end
```
cat -path /etc/shadow -start 5
```

### Show with line numbers
```
cat -path /etc/hosts -number true
```

### Line range with numbering
```
cat -path config.yml -start 20 -end 40 -number true
```

### Override size limit for larger files
```
cat -path /var/log/syslog -max 10240
```

## Size Protection

Files larger than 5MB (5120 KB) are rejected by default. This prevents the agent from consuming excessive memory on large log files or databases. When this happens, the command suggests:

- Use `tail` for reading the first/last N lines or bytes of large files
- Use `-max` to override the limit if you really need the full file

When using line range mode (`-start`/`-end`), output is also truncated if it exceeds the max size.

## MITRE ATT&CK Mapping

- **T1005** — Data from Local System
