+++
title = "syscalls"
chapter = false
weight = 161
hidden = false
+++

## Summary

Show and manage the indirect syscall resolver. When active, injection commands use Nt* syscalls via stubs that jump to ntdll's own `syscall;ret` gadget, making API calls appear to originate from ntdll and bypassing userland API hooks.

{{% notice info %}}Windows Only{{% /notice %}}

## How Indirect Syscalls Work

1. **Resolve**: Parse ntdll's PE export table to extract syscall numbers using Hell's Gate pattern (`mov r10, rcx; mov eax, <num>`)
2. **Halo's Gate**: If a function is hooked (different prologue), calculate its syscall number from neighboring unhooked exports
3. **Stub Generation**: Allocate executable memory and write indirect stubs: `mov r10, rcx; mov eax, N; jmp [ntdll_syscall_ret]`
4. **Execution**: Injection commands call stubs via `syscall.SyscallN` — the actual `syscall` instruction executes from within ntdll's address space

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action   | No       | status  | Action: `status`, `list`, or `init` |

## Actions

- **status** — Show whether indirect syscalls are active and how many Nt* functions are resolved
- **list** — Show all resolved Nt* syscalls with their numbers and stub status
- **init** — Initialize the indirect syscall resolver (if not already enabled via build parameter)

## Usage

```
# Check if indirect syscalls are active
syscalls

# List all resolved Nt* syscalls with numbers
syscalls -action list

# Initialize at runtime (if not enabled via build parameter)
syscalls -action init
```

## Build Parameter

Enable `indirect_syscalls` in the payload build options to automatically initialize at startup. When enabled, injection commands (vanilla-injection, etc.) automatically use indirect syscalls.

## Integrated Commands

When indirect syscalls are active, these commands use Nt* APIs via indirect stubs:
- **vanilla-injection** — NtOpenProcess, NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx
- **execute-shellcode** — NtAllocateVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx (in-process)
- **hollow** — NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory, NtGetContextThread, NtSetContextThread, NtResumeThread

## MITRE ATT&CK Mapping

- T1106 — Native API
