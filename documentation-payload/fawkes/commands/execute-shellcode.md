+++
title = "execute-shellcode"
chapter = false
weight = 105
hidden = false
+++

## Summary

Execute raw shellcode in the current agent process. The shellcode is loaded into a new memory allocation and executed in a new thread within the agent process.

Unlike process injection commands (vanilla-injection, apc-injection, etc.), this runs shellcode in the agent's own process without crossing process boundaries. This avoids cross-process injection detection but means the shellcode shares the agent's address space.

### Platform Details

| Platform | Allocation | Execution | Notes |
|----------|-----------|-----------|-------|
| Windows | VirtualAlloc (RW) + VirtualProtect (RX) | CreateThread | Standard W^X allocation pattern |
| Linux | mmap (RW) + mprotect (RX) | New goroutine via syscall | Uses anonymous private mapping |
| macOS (ARM64) | mmap with MAP_JIT | pthread_jit_write_protect_np + new goroutine | Apple Silicon requires MAP_JIT for writable-then-executable memory |
| macOS (x86_64) | mmap (RW) + mprotect (RX) | New goroutine via syscall | Same pattern as Linux |

## Arguments

Shellcode can be provided via Mythic file upload (UI) or base64-encoded string (API).

| Argument | Required | Description |
|----------|----------|-------------|
| filename | Yes (Default group) | Select a shellcode file already registered in Mythic |
| file | Yes (New File group) | Upload a new shellcode file |
| shellcode_b64 | Yes (CLI group) | Base64-encoded raw shellcode bytes |

## Usage

```
# From Mythic UI: select a previously uploaded shellcode file from the dropdown
execute-shellcode -filename my_shellcode.bin

# From API: provide base64-encoded shellcode
execute-shellcode -shellcode_b64 "kJBQ..."
```

## OPSEC Considerations

- **Windows:** VirtualAlloc with PAGE_READWRITE followed by VirtualProtect to PAGE_EXECUTE_READ; CreateThread API call is monitored by many EDR products
- **Linux:** mmap + mprotect syscalls; less commonly monitored but auditable via seccomp/auditd
- **macOS (ARM64):** MAP_JIT allocations are visible to endpoint security frameworks; pthread_jit_write_protect_np transitions are trackable
- **macOS (x86_64):** mmap + mprotect pattern similar to Linux
- Shellcode runs in the agent process — if it crashes, the agent dies
- No cross-process artifacts (no OpenProcess, no WriteProcessMemory, no ptrace)
- Memory allocation and thread creation are in the agent's own process

## MITRE ATT&CK Mapping

- **T1059.006** — Command and Scripting Interpreter: Python (shellcode execution)
- **T1055.012** — Process Injection: Process Hollowing (memory allocation + execution)
