+++
title = "strings"
chapter = false
weight = 178
hidden = false
+++

## Summary

Extract printable ASCII strings from files. Useful for binary analysis — finding embedded URLs, credentials, error messages, function names, and other text in executables, DLLs, and other binary files without downloading them.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| path | Yes | | Path to the file to extract strings from |
| min_length | No | 4 | Minimum string length (characters) |
| offset | No | 0 | Byte offset to start scanning from |
| max_size | No | 10MB | Maximum bytes to scan |
| pattern | No | | Only show strings containing this text (case-insensitive) |

## Usage

Extract all strings from a binary:
```
strings -path /usr/bin/ssh
```

Find URLs in an executable:
```
strings -path C:\Windows\System32\cmd.exe -pattern http
```

Extract long strings (min 20 chars) from a binary:
```
strings -path /tmp/suspicious.bin -min_length 20
```

Search for passwords or credentials:
```
strings -path malware.exe -pattern password
```

Scan only the first 1MB of a large file:
```
strings -path /var/log/app.bin -max_size 1048576
```

## MITRE ATT&CK Mapping

- **T1005** — Data from Local System
- **T1083** — File and Directory Discovery
