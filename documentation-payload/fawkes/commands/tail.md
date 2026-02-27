+++
title = "tail"
chapter = false
weight = 180
hidden = false
+++

## Summary

Read the first or last N lines (or bytes) of a file without transferring the entire contents. Useful for reading logs, checking config files, and handling large files efficiently. Avoids spawning subprocesses.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| path | Yes | Path to the file to read |
| lines | No | Number of lines to read (default: 10) |
| head | No | Read from the beginning instead of the end (default: `false`) |
| bytes | No | Read N bytes instead of lines (0 = use lines mode) |

## Usage

### Last 10 lines (default)
```
tail -path /var/log/auth.log
```

### First 5 lines (head mode)
```
tail -path /etc/passwd -lines 5 -head true
```

### Last 50 lines of a log
```
tail -path /var/log/syslog -lines 50
```

### Last 256 bytes (binary/raw mode)
```
tail -path /tmp/data.bin -bytes 256
```

### First 1024 bytes
```
tail -path C:\Windows\System32\config\SAM -bytes 1024 -head true
```

## Output

```
[*] last 10 lines of /var/log/auth.log (45.2 KB)
Feb 27 00:01:22 host sshd[1234]: Accepted publickey for user from 10.0.0.1
Feb 27 00:01:22 host sshd[1234]: pam_unix(sshd:session): session opened
...
```

### Head mode
```
[*] first 5 lines of /etc/passwd (2.9 KB)
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

### Bytes mode
```
[*] last 256 bytes of /tmp/data.bin (1.2 MB total)
<raw content>
```

## OPSEC Considerations

- **No subprocess**: Uses Go's `os.Open` and `bufio.Scanner` — no external commands spawned
- **Memory efficient**: Ring buffer for tail reads, reverse-seek for files >10MB
- **Read-only**: Does not modify the file

## MITRE ATT&CK Mapping

- T1005 — Data from Local System
- T1083 — File and Directory Discovery
