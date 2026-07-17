+++
title = "hollow"
chapter = false
weight = 202
hidden = false
+++

## Summary

Process hollowing — create a suspended process and redirect execution to shellcode.

**Windows:** Creates a new process with CREATE_SUSPENDED, allocates memory, writes shellcode, updates thread context (RCX), resumes. Supports PPID spoofing and non-Microsoft DLL blocking.

**Linux (amd64/arm64):** Spawns a process with PTRACE_TRACEME (stopped at exec), finds a syscall gadget (0x0F 0x05 on amd64, SVC #0 on arm64), allocates memory via remote mmap, writes shellcode through /proc/PID/mem, redirects execution (RIP on amd64, PC on arm64), and detaches. Default target: `/usr/bin/sleep`.

**macOS (ARM64):** Spawns a process with PT_TRACE_ME (stopped at exec), obtains the child's Mach task port via `task_for_pid`, allocates RW memory via `mach_vm_allocate`, writes shellcode via `mach_vm_write`, changes protection to RX via `mach_vm_protect`, and redirects the instruction pointer using `ptrace(PT_DETACH, pid, shellcode_addr, 0)`. Requires root. Default target: `/bin/sleep`.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| filename | Yes (Default group) | Select shellcode from files registered in Mythic |
| file | Yes (New File group) | Upload a new shellcode file |
| shellcode_b64 | Yes (CLI group) | Base64-encoded raw shellcode bytes |
| target | No | Process to create and hollow. Windows default: `svchost.exe`. Linux default: `/usr/bin/sleep`. macOS default: `/bin/sleep` |
| ppid | No | Parent PID to spoof (Windows only, 0 = no spoofing) |
| block_dlls | No | Block non-Microsoft DLLs (Windows only, default: false) |
| stack_spoof | No | Spoof the call stack during injection API calls. Executes Nt* syscalls from a dedicated thread with fake kernel32/ntdll return frames, evading EDR thread stack scanners. Requires `indirect_syscalls` and `stack_spoof` build options. Default: `false`. |

## Usage

```
# Windows: from Mythic UI
hollow -filename beacon.bin -target C:\Windows\System32\RuntimeBroker.exe

# Windows: with PPID spoofing
hollow -filename beacon.bin -ppid 1234 -block_dlls true

# Linux: from CLI
hollow -shellcode_b64 "kJBQ..." -target /usr/bin/cat

# Linux: default target (sleep 86400)
hollow -shellcode_b64 "kJBQ..."

# macOS (requires root): default target
hollow -shellcode_b64 "HyAD1cADX9Y="

# macOS: custom target
hollow -shellcode_b64 "HyAD1cADX9Y=" -target "/usr/bin/yes"
```

## OPSEC Considerations

### Windows
- Creates suspended process, allocates/writes cross-process memory, modifies thread context
- **PEB decoration:** Automatically overwrites ImagePathName, CommandLine, and WindowTitle in the hollowed process's PEB to match the legitimate target executable. Makes the process indistinguishable from a real instance in Task Manager and PEB inspection tools.
- PPID spoofing and DLL blocking via extended startup attributes
- Highly signatured by EDR (Sysmon Event IDs 1, 8, 10)

### Linux
- Requires ptrace capability (Yama ptrace_scope 0 or CAP_SYS_PTRACE)
- /proc/PID/mem write avoids PTRACE_POKETEXT monitoring
- Process creation + ptrace attach sequence may trigger audit rules

### macOS
- Requires root (task_for_pid needs root or com.apple.security.cs.debugger entitlement)
- Uses Mach VM APIs: task_for_pid, mach_vm_allocate, mach_vm_write, mach_vm_protect
- Detectable by Endpoint Security framework (ES_EVENT_TYPE_NOTIFY_MACH_TRAP, ES_EVENT_TYPE_NOTIFY_SIGNAL)
- ptrace-based process control visible to process monitors
- SIP-protected binaries cannot be targeted

## MITRE ATT&CK Mapping

- **T1055.012** — Process Injection: Process Hollowing
- **T1055.009** — Process Injection: Proc Memory (Linux)
- **T1036** — Masquerading (PEB decoration)
