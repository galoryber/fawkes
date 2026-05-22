+++
title = "apc-injection"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Remote-process shellcode injection. Two methods are supported:

- **APC** (default, `-method apc`) — Queues an asynchronous procedure call via `NtQueueApcThread` into a thread that is in an alertable wait state (Suspended or DelayExecution). Requires a target TID.
- **HWBP** (`-method hwbp`) — Attaches as a debugger via `DebugActiveProcess`, sets a DR0 hardware execution breakpoint on a target API (default `ntdll!NtDelayExecution`) in every thread of the target process, waits for the breakpoint to fire via `WaitForDebugEvent`, and redirects the affected thread's `Rip` to the shellcode buffer with `SetThreadContext`. The debugger detaches via `DebugActiveProcessStop` and the target keeps running. No TID is required, no APC is queued, and no `CreateRemoteThread` is called.

When indirect syscalls are enabled (build parameter), both paths route their memory and thread operations through Nt* indirect stubs: `NtOpenProcess`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `NtOpenThread`, `NtGetContextThread`, `NtSetContextThread`, `NtQueueApcThread`. Memory follows W^X (allocate RW, write, protect RX). Debug-event APIs (DebugActiveProcess, WaitForDebugEvent, ContinueDebugEvent) are not currently routed through indirect syscalls — they are kernel32 wrappers.

## Arguments

### Shellcode File / File / shellcode_b64
Select a shellcode file already registered in Mythic, upload a new one, or provide base64 directly via the CLI.

### Target PID
The process ID to inject into. Required for both methods.

### Target Thread ID (`tid`)
Required only for `method=apc`. Use the `ts` command first to identify alertable threads (Suspended/DelayExecution state). Ignored for `method=hwbp`.

### Injection Method (`method`)
- `apc` — QueueUserAPC into the specified TID (default).
- `hwbp` — DebugActiveProcess + DR0 redirect.

### HWBP Breakpoint API (`target_api`)
HWBP method only. Format: `module!function`. Default: `ntdll!NtDelayExecution`.

The address is resolved in the agent process via LoadLibrary/FindProc, then assumed to be valid in the target. This is true for **`ntdll.dll`** and other KnownDlls because Windows maps them at the same base in every process within a session. It is **not** safe for arbitrary user-loaded modules whose load addresses may differ. Pick a function the target calls frequently — `ntdll!NtDelayExecution`, `ntdll!NtWaitForSingleObject`, `ntdll!NtTestAlert` are good candidates because the kernel and runtime call them constantly.

### HWBP Timeout (`timeout_ms`)
HWBP method only. Maximum time to wait for the breakpoint to fire and a thread to be redirected. Default 30000 (30s). On timeout, DR0/DR7 are cleared on every thread (best-effort) and the debugger detaches before the call returns the failure.

### Stack Spoof (`stack_spoof`)
Spoof the call stack during injection API calls. Executes Nt* syscalls from a dedicated thread with fake kernel32/ntdll return frames, evading EDR thread stack scanners. Requires `indirect_syscalls` and `stack_spoof` build options. Default: `false`.

## Usage

### APC (default)

1. Run `ts -i <PID>` to find alertable threads in the target process.
2. Use the Mythic UI popup to select shellcode, PID, and TID.

```
ts -i 5432
apc-injection
```

### HWBP

1. Pick any user-mode process you have `PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION` access to. PPL / protected processes (LSASS, csrss, etc.) will reject `DebugActiveProcess`. Do not target the agent's own PID.
2. Set `method = hwbp`, leave `target_api` at the default unless you have a reason to change it.

```
apc-injection -method hwbp -pid 5432
```

The trace returned in the task output captures: API address resolved, shellcode allocation address, threads armed, breakpoint hits, redirected TID, and detach status.

## OPSEC

- **APC method**: NtQueueApcThread is monitored by advanced EDRs but less aggressively than CreateRemoteThread.
- **HWBP method**: `DebugActiveProcess` produces a Sysmon EID 10 (ProcessAccess) with `PROCESS_ALL_ACCESS` and the `DEBUG_PROCESS` access mask. Cross-process `VirtualAllocEx + WriteProcessMemory` and `SetThreadContext` are also high-fidelity detections. Avoid targeting protected / PPL processes — DebugActiveProcess will fail. The technique avoids the most common injection signatures (CreateRemoteThread, QueueUserAPC, NtMapViewOfSection cross-process) but introduces a debugger-attach signal in their place.

## MITRE ATT&CK Mapping

- T1055.004 — Process Injection: Asynchronous Procedure Call (APC method)
- T1055 — Process Injection (HWBP method, generic)
