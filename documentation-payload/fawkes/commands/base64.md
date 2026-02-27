+++
title = "base64"
chapter = false
weight = 105
hidden = false
+++

## Summary

Encode or decode base64 content — strings and files. Optionally write results to a file. Useful for data staging, encoding payloads for transport, and processing encoded data found during reconnaissance. No subprocess spawned.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | No | `encode` or `decode` (default: `encode`) |
| input | Yes | String to process, or file path if `-file true` |
| file | No | Treat input as a file path (default: `false`) |
| output | No | Write result to this file instead of displaying |

## Usage

### Encode a string
```
base64 -input "hello world"
```

### Decode a string
```
base64 -action decode -input "aGVsbG8gd29ybGQ="
```

### Encode a file
```
base64 -input /etc/passwd -file true
```

### Decode to output file
```
base64 -action decode -input "SGVsbG8=" -output /tmp/decoded.bin
```

### Encode file and save to disk
```
base64 -input /tmp/payload.exe -file true -output /tmp/payload.b64
```

## Output

### Encode
```
[*] Encoded 11 bytes from string
aGVsbG8gd29ybGQ=
```

### Decode
```
[*] Decoded 16 chars from string → 11 bytes
hello world
```

### File output
```
[+] Decoded 24 chars → 18 bytes, written to /tmp/decoded.bin
```

## OPSEC Considerations

- **No subprocess**: Uses Go's `encoding/base64` — no external commands spawned
- **Memory**: Large files are loaded into memory for encoding/decoding
- **Disk writes**: Output file option writes to disk (detectable by file monitoring)

## MITRE ATT&CK Mapping

- T1132.001 — Data Encoding: Standard Encoding
- T1027 — Obfuscated Files or Information
