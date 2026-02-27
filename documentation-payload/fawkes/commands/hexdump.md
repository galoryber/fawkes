+++
title = "hexdump"
chapter = false
weight = 150
hidden = false
+++

## Summary

Display a hex dump of file contents in xxd-style format. Inspect binary files on-target without downloading them. Supports byte offset and length control for examining specific regions of large files.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| path | Yes | Path to file to hex dump |
| offset | No | Starting byte offset (default: 0) |
| length | No | Number of bytes to display (default: 256, max: 4096) |

## Usage

### Default hex dump (first 256 bytes)
```
hexdump -path /tmp/payload.bin
```

### Inspect PE header
```
hexdump -path C:\Windows\System32\cmd.exe -length 512
```

### Read from specific offset
```
hexdump -path /usr/bin/ls -offset 1024 -length 128
```

### Check ELF magic bytes
```
hexdump -path /bin/bash -length 16
```

## Output

```
[*] /tmp/payload.bin (1.2 KB) — offset 0x00000000, 256 bytes
00000000: 4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............|
00000010: b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
00000020: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
...
```

## OPSEC Considerations

- **No subprocess**: Uses Go's `os.Open` and direct file reading
- **Read-only**: Does not modify the file
- **Memory efficient**: Only reads the requested byte range, never the full file
- **Output capped**: Maximum 4096 bytes per request to prevent excessive output

## MITRE ATT&CK Mapping

- T1005 — Data from Local System
- T1083 — File and Directory Discovery
