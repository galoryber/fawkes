+++
title = "execute-memory"
chapter = false
weight = 100
hidden = false
+++

## Summary

Execute an ELF binary entirely from memory using Linux's `memfd_create` system call. The binary never touches disk — it exists only in an anonymous memory-backed file descriptor, making it invisible to traditional file-based detection.

{{% notice info %}}Linux Only{{% /notice %}}

## How It Works

1. `memfd_create("")` creates an anonymous file backed by memory
2. The ELF binary is written to this memory file descriptor
3. The binary is executed via `/proc/<pid>/fd/<fd>` path
4. stdout/stderr are captured and returned
5. The memfd is closed and the memory is freed

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| file/filename/binary_b64 | Yes | The ELF binary to execute (upload, select existing, or base64-encode) |
| arguments | No | Command-line arguments to pass to the binary |
| timeout | No | Execution timeout in seconds (default: 60) |

## Usage

**Via Mythic UI:** Upload an ELF binary or select a previously uploaded one, optionally provide arguments.

**Via CLI/API:**
```
execute-memory -binary_b64 <base64_elf> -arguments "-h" -timeout 30
```

## Examples

Execute a static Linux binary from memory:
```
execute-memory (upload file via UI) -arguments "--scan 192.168.1.0/24"
```

Execute with timeout:
```
execute-memory (upload file via UI) -arguments "-v" -timeout 120
```

## Notes

- Binary must be a valid ELF executable (magic bytes are validated)
- Static binaries work best — dynamically linked binaries require shared libraries to be present on the target
- The binary appears in `ps` output as `/proc/<pid>/fd/<N>` or `memfd:` rather than a file path
- Requires Linux kernel 3.17+ (memfd_create support)
- Maximum binary size is limited by available memory

## MITRE ATT&CK Mapping

- **T1620** — Reflective Code Loading
