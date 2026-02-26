+++
title = "thread-hijack"
chapter = false
weight = 104
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Inject shellcode via thread execution hijacking. Suspends an existing thread in a remote process, modifies its instruction pointer (RIP) to point to injected shellcode, and resumes execution. This avoids creating new threads (`CreateRemoteThread`/`NtCreateThreadEx`) which are heavily monitored by EDR solutions.

When indirect syscalls are enabled (build parameter), core APIs use Nt* indirect stubs:
- Process: NtOpenProcess
- Memory: NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory
- Thread: NtOpenThread, NtGetContextThread, NtSetContextThread, NtResumeThread

Memory follows W^X pattern (allocate RW, write shellcode, change to RX).

### How It Works

1. **Open target process** with required access rights
2. **Allocate RW memory**, write shellcode, change protection to RX (W^X)
3. **Enumerate threads** via CreateToolhelp32Snapshot
4. **Select target thread** — user-specified TID or auto-select first non-main thread
5. **Open and suspend** the target thread
6. **Get thread context** and save the original RIP
7. **Set RIP** to the shellcode address
8. **Set modified context** and resume the thread

### Arguments

#### Shellcode File
Select a shellcode file already registered in Mythic, or upload a new shellcode file. For API/CLI usage, provide base64-encoded shellcode via the `shellcode_b64` parameter.

#### Target PID
The process ID to inject shellcode into.

#### Target TID
Specific thread ID to hijack (optional). Set to 0 or leave empty for auto-selection, which picks the first non-main thread in the target process.

## Usage

Use the Mythic UI popup to select shellcode, target PID, and optionally a specific thread ID.

```
# Via API/CLI with base64 shellcode (auto-select thread)
thread-hijack -shellcode_b64 <base64> -pid 1234

# With specific thread ID
thread-hijack -shellcode_b64 <base64> -pid 1234 -tid 5678
```

## Opsec Considerations

- No new threads created — avoids `CreateRemoteThread`/`NtCreateThreadEx` detection
- Thread suspension is brief — context is modified and resumed quickly
- Shellcode allocated in private memory (RX) — standard memory scanning can detect it
- Using indirect syscalls hides NtOpenProcess, NtOpenThread, and context manipulation calls
- Consider pairing with module-stomping for the memory allocation if private RX detection is a concern

## MITRE ATT&CK Mapping

- T1055.003 — Process Injection: Thread Execution Hijacking
