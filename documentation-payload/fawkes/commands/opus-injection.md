+++
title = "opus-injection"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Callback-based process injection techniques that achieve code execution through manipulation of Windows callback tables and handler chains. Two variants are available targeting different process types.

When indirect syscalls are enabled (build parameter), uses Nt* APIs via indirect stubs: NtOpenProcess, NtAllocateVirtualMemory, NtWriteVirtualMemory, NtReadVirtualMemory, NtProtectVirtualMemory, NtClose. Memory follows W^X pattern (allocate RW, write, protect RX).

### Arguments

#### Injection Variant
- **Variant 1 - Ctrl-C Handler Chain** - Targets console processes only (cmd.exe, powershell.exe, etc.)
- **Variant 4 - KernelCallbackTable** - Targets GUI processes only (notepad.exe, explorer.exe, etc.)

#### Shellcode File
Select a shellcode file already registered in Mythic, or upload a new shellcode file.

#### Target PID
The process ID to inject into. Must match the variant type (console process for Variant 1, GUI process for Variant 4).

#### CFG Bypass (default: enabled)
When enabled, calls `SetProcessValidCallTargets` on the shellcode allocation to mark it as a valid Control Flow Guard call target before the callback executes. Required on Windows 10/11 targets with CFG-enabled processes (most system processes). Disable only if the API call itself triggers EDR detection.

#### Stack Spoof (`stack_spoof`)
Spoof the call stack during injection API calls. Executes Nt* syscalls from a dedicated thread with fake kernel32/ntdll return frames, evading EDR thread stack scanners. Requires `indirect_syscalls` and `stack_spoof` build options. Default: `false`.

## Usage

Use the Mythic UI popup to select the variant, shellcode, and target PID.

## Go Shellcode Compatibility

| Variant | Target | Go Shellcode Compatible |
|---------|--------|------------------------|
| 1 - Ctrl-C Handler Chain | Console processes | No |
| 4 - KernelCallbackTable | GUI processes | Yes |

## Detailed Summary

**Variant 1** injects a fake handler into the target's console Ctrl+C handler array in kernelbase.dll, then triggers a Ctrl+C event. No CreateRemoteThread or APC calls.

**Variant 4** modifies the PEB KernelCallbackTable pointer to redirect the `__fnCOPYDATA` callback, then triggers execution via a WM_COPYDATA window message. Both the injector and injected agent can operate simultaneously.

## MITRE ATT&CK Mapping

- T1055
