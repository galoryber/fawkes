+++
title = "execute-memory"
chapter = false
weight = 100
hidden = false
+++

## Summary

Execute a native binary from memory with minimal forensic footprint. Platform-specific implementations ensure the most covert execution method available on each OS.

{{% notice info %}}Cross-Platform: Windows, Linux, macOS{{% /notice %}}

## How It Works

### Linux (memfd_create)
1. `memfd_create("")` creates an anonymous file backed by memory
2. The ELF binary is written to this memory file descriptor
3. The binary is executed via `/proc/<pid>/fd/<fd>` path
4. stdout/stderr are captured and returned
5. The memfd is closed and the memory is freed

No file is ever written to disk — the binary exists only in an anonymous memory-backed file descriptor.

### macOS (temp file + codesign)
1. A temp file is created in the system temp directory
2. The Mach-O binary is written and made executable
3. Ad-hoc code signing is applied (`codesign -s -`) — required on Apple Silicon (arm64)
4. The binary is executed with timeout enforcement
5. The temp file is removed immediately after execution completes

The temp file exists only for the duration of execution. Apple Silicon requires code signatures even for ad-hoc signed binaries, and macOS validates signatures at runtime (the file must persist while the process runs).

### Windows (temp file + CreateProcess)
1. The PE binary is validated (MZ header + PE signature at NT header offset)
2. A temp file is created with a randomized name and `.exe` extension
3. The binary is written and executed via `CreateProcess`
4. stdout/stderr are captured and returned
5. The temp file is removed immediately after execution completes

The temp file exists only for the duration of execution. This approach handles both x86 and x64 PE binaries.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| file/filename/binary_b64 | Yes | The native binary to execute (upload, select existing, or base64-encode) |
| arguments | No | Command-line arguments to pass to the binary |
| timeout | No | Execution timeout in seconds (default: 60) |

## Usage

**Via Mythic UI:** Upload a native binary (PE for Windows, ELF for Linux, Mach-O for macOS) or select a previously uploaded one, optionally provide arguments.

**Via CLI/API:**
```
execute-memory -binary_b64 <base64_binary> -arguments "-h" -timeout 30
```

## Examples

Execute a static binary from memory:
```
execute-memory (upload file via UI) -arguments "--scan 192.168.1.0/24"
```

Execute with timeout:
```
execute-memory (upload file via UI) -arguments "-v" -timeout 120
```

## Notes

- **Windows:** Binary must be a valid PE executable (MZ header + PE signature validated). Temp file is created with randomized name and `.exe` extension, removed immediately after execution.
- **Linux:** Binary must be a valid ELF executable (magic bytes validated). Requires kernel 3.17+ for memfd_create. Binary appears in `ps` as `/proc/<pid>/fd/<N>` or `memfd:`.
- **macOS:** Binary must be a valid Mach-O executable (all 6 magic variants validated: 32/64-bit, universal/fat binaries). Ad-hoc codesign is applied automatically — required on Apple Silicon.
- Static binaries work best — dynamically linked binaries require shared libraries on the target
- Maximum binary size is limited by available memory

## MITRE ATT&CK Mapping

- **T1620** — Reflective Code Loading
