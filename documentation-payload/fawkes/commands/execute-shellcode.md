+++
title = "execute-shellcode"
chapter = false
weight = 105
hidden = false
+++

## Summary

Execute raw shellcode in the current agent process. The shellcode is loaded into a new memory allocation and executed in a new thread within the agent process.

Unlike process injection commands (vanilla-injection, apc-injection, etc.), this runs shellcode in the agent's own process without crossing process boundaries.

### Platform Details

| Platform | Technique | Allocation | Execution | Notes |
|----------|-----------|-----------|-----------|-------|
| Windows | (default) | VirtualAlloc (RW) + VirtualProtect (RX) | CreateThread | Standard W^X allocation |
| Linux | `mmap` (default) | Anonymous mmap (RW) + mprotect (RX) | New goroutine | Standard anonymous mapping |
| Linux | `memfd` | memfd_create + mmap (RX) | New goroutine | fd-backed mapping evades anonymous RX detection |
| macOS (ARM64) | (default) | mmap with MAP_JIT | pthread_jit_write_protect_np | Apple Silicon requires MAP_JIT |
| macOS (x86_64) | (default) | mmap (RW) + mprotect (RX) | New goroutine | Same pattern as Linux mmap |

### Technique Details (Linux)

**mmap (default):** Creates an anonymous private mapping with PROT_READ|PROT_WRITE, copies shellcode, then transitions to PROT_READ|PROT_EXEC. The memory appears as an anonymous executable region in /proc/self/maps.

**memfd:** Uses memfd_create(2) to create an anonymous file descriptor, writes shellcode to it, seals it read-only, then mmaps the fd with PROT_READ|PROT_EXEC. The resulting memory appears as a file-backed executable region rather than an anonymous one, evading detection rules that flag anonymous RX mappings.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| filename | Yes (Default group) | Select a shellcode file already registered in Mythic |
| file | Yes (New File group) | Upload a new shellcode file |
| shellcode_b64 | Yes (CLI group) | Base64-encoded raw shellcode bytes |
| technique | No | `mmap` (default) or `memfd` (Linux only). Selects the memory allocation technique. |

## Usage

```
# From Mythic UI: select shellcode, optionally set technique
execute-shellcode -filename my_shellcode.bin

# Linux: use memfd technique to evade anonymous mapping detection
execute-shellcode -filename my_shellcode.bin -technique memfd

# From API
execute-shellcode -shellcode_b64 "kJBQ..." -technique memfd
```

## OPSEC Considerations

- **Windows:** VirtualAlloc + VirtualProtect + CreateThread — monitored by most EDR
- **Linux (mmap):** Anonymous RX region in /proc/self/maps; auditable via seccomp/auditd
- **Linux (memfd):** fd-backed RX region appears more legitimate; memfd_create itself may be monitored
- **macOS (ARM64):** MAP_JIT allocations visible to Endpoint Security framework
- Shellcode runs in the agent process — if it crashes, the agent dies
- No cross-process artifacts

## MITRE ATT&CK Mapping

- **T1059.006** — Command and Scripting Interpreter (shellcode execution)
- **T1620** — Reflective Code Loading (memfd technique)
