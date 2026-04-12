+++
title = "base64"
chapter = false
weight = 105
hidden = false
+++

## Summary

Data encoding toolkit — base64, XOR, hex, ROT13, URL percent-encoding, and Caesar cipher. Supports string and file input/output. Useful for data obfuscation, payload encoding, deobfuscating captured data, and processing encoded artifacts found during reconnaissance. No subprocess spawned — all operations use Go standard library.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | No | Algorithm: `encode`, `decode` (base64), `xor`, `hex`, `hex-decode`, `rot13`, `url`, `url-decode`, `caesar` (default: `encode`) |
| input | Yes | String to process, or file path if `-file true` |
| file | No | Treat input as a file path (default: `false`) |
| output | No | Write result to this file instead of displaying |
| key | No | XOR key — plain string or hex with `0x` prefix (e.g., `secret` or `0x41424344`) |
| shift | No | Caesar cipher shift value (1-25, negative to decode) |

## Usage

### Base64 encode/decode
```
base64 -input "hello world"
base64 -action decode -input "aGVsbG8gd29ybGQ="
base64 -input /etc/passwd -file true
base64 -action decode -input "SGVsbG8=" -output /tmp/decoded.bin
```

### XOR encode/decode (symmetric)
```
base64 -action xor -input "secret data" -key "mykey"
base64 -action xor -input "secret data" -key 0x41424344
base64 -action xor -input /tmp/encrypted.bin -file true -key "mykey" -output /tmp/decrypted.bin
```

### Hex encode/decode
```
base64 -action hex -input "Hello World"
base64 -action hex-decode -input "48656c6c6f20576f726c64"
base64 -action hex -input /tmp/binary.exe -file true -output /tmp/hex.txt
```

### ROT13 (symmetric)
```
base64 -action rot13 -input "Hello World"
base64 -action rot13 -input "Uryyb Jbeyq"
```

### URL encode/decode
```
base64 -action url -input "param=value&foo=bar baz"
base64 -action url-decode -input "hello%20world%26foo%3Dbar"
```

### Caesar cipher
```
base64 -action caesar -input "Attack at dawn" -shift 3
base64 -action caesar -input "Dwwdfn dw gdzq" -shift -3
```

## Output

### XOR (hex output when no output file)
```
[*] XOR 11 bytes from string (key: 5 bytes)
1a0e120b050a170e1c06
```

### Hex encode
```
[*] Hex encode 11 bytes from string
48656c6c6f20576f726c64
```

### ROT13
```
[*] ROT13 11 bytes from string
Uryyb Jbeyq
```

### Caesar
```
[*] Caesar (shift 3) 14 bytes from string
Dwwdfn dw gdzq
```

## OPSEC Considerations

- **No subprocess**: All algorithms use Go standard library — no external commands spawned
- **XOR**: Commonly associated with malware obfuscation — flagged in OPSEC pre-check
- **Memory**: Large files are loaded into memory for processing
- **Disk writes**: Output file option writes to disk (detectable by file monitoring)
- **Sensitive data**: Memory is zeroed after processing where possible

## MITRE ATT&CK Mapping

- T1132.001 — Data Encoding: Standard Encoding
- T1027 — Obfuscated Files or Information
- T1140 — Deobfuscate/Decode Files or Information
