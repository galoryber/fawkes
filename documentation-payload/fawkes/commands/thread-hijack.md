+++
title = "thread-hijack"
chapter = false
weight = 104
hidden = false
+++

{{% notice info %}}
Windows and macOS
{{% /notice %}}

## Summary

Inject shellcode via thread execution hijacking. Suspends an existing thread in a remote process, modifies its instruction pointer (PC/RIP) to point to injected shellcode, and resumes execution. This avoids creating new threads which are heavily monitored by EDR solutions.

### Windows

When indirect syscalls are enabled (build parameter), core APIs use Nt* indirect stubs:
- Process: NtOpenProcess
- Memory: NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory
- Thread: NtOpenThread, NtGetContextThread, NtSetContextThread, NtResumeThread

Memory follows W^X pattern (allocate RW, write shellcode, change to RX).

#### How It Works (Windows)

1. **Open target process** with required access rights
2. **Allocate RW memory**, write shellcode, change protection to RX (W^X)
3. **Enumerate threads** via CreateToolhelp32Snapshot
4. **Select target thread** — user-specified TID or auto-select first non-main thread
5. **Open and suspend** the target thread
6. **Get thread context** and save the original RIP
7. **Set RIP** to the shellcode address
8. **Set modified context** and resume the thread

### macOS (ARM64)

Uses pure-Go Mach API wrappers via assembly trampolines — no CGO required. Requires root for `task_for_pid`.

#### How It Works (macOS)

1. **Get task port** via `task_for_pid` (requires root)
2. **Enumerate threads** via `task_threads` MIG call
3. **Select target thread** — user-specified or auto-select first thread
4. **Suspend thread** via `thread_suspend`
5. **Allocate RW memory** in target via `mach_vm_allocate`, write shellcode via `mach_vm_write`, change to RX
6. **Allocate stack** (64KB) for shellcode execution
7. **Get thread state** via `thread_get_state` (ARM64 register set)
8. **Redirect PC** to shellcode address, set SP to new stack
9. **Set thread state** and resume via `thread_resume`

### Arguments

#### Shellcode File
Select a shellcode file already registered in Mythic, or upload a new shellcode file. For API/CLI usage, provide base64-encoded shellcode via the `shellcode_b64` parameter.

#### Target PID
The process ID to inject shellcode into.

#### Target TID
Specific thread ID to hijack (optional). Set to 0 or leave empty for auto-selection, which picks the first non-main thread (Windows) or first thread (macOS) in the target process.

## Usage

Use the Mythic UI popup to select shellcode, target PID, and optionally a specific thread ID.

```
# Via API/CLI with base64 shellcode (auto-select thread)
thread-hijack -shellcode_b64 <base64> -pid 1234

# With specific thread ID
thread-hijack -shellcode_b64 <base64> -pid 1234 -tid 5678
```

## Opsec Considerations

### Windows
- No new threads created — avoids `CreateRemoteThread`/`NtCreateThreadEx` detection
- Thread suspension is brief — context is modified and resumed quickly
- Shellcode allocated in private memory (RX) — standard memory scanning can detect it
- Using indirect syscalls hides NtOpenProcess, NtOpenThread, and context manipulation calls
- Consider pairing with module-stomping for the memory allocation if private RX detection is a concern

### macOS
- Requires root privileges — `task_for_pid` is restricted by macOS security
- `task_for_pid` generates `ES_EVENT_TYPE_NOTIFY_MACH_TRAP` events visible to Endpoint Security framework
- Thread state manipulation via Mach APIs is less commonly monitored than Windows equivalents
- No new threads created — existing thread is redirected
- Memory allocated via `mach_vm_allocate` is in the target's address space (RX)
- SIP (System Integrity Protection) prevents injection into Apple-signed system processes

## MITRE ATT&CK Mapping

- T1055.003 — Process Injection: Thread Execution Hijacking
