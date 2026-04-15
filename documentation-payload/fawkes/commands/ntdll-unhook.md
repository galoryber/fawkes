+++
title = "ntdll-unhook"
chapter = false
weight = 108
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Remove EDR (Endpoint Detection and Response) inline hooks from DLLs by restoring the `.text` section from a clean copy. Supports `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`, `advapi32.dll`, `user32.dll`, or all five at once.

### How EDR Hooking Works

EDR products inject monitoring DLLs into every user-mode process. These DLLs overwrite the first few bytes of key functions (e.g., `NtAllocateVirtualMemory`, `CreateProcessW`, `VirtualAlloc`) with `JMP` instructions that redirect to the EDR's inspection trampoline. This allows the EDR to inspect all API arguments before they execute.

### How Unhooking Works

Two source methods are available for obtaining the clean DLL copy:

**Disk (default):** Read from `C:\Windows\System32\<dll>` using `CreateFileW` + `SEC_IMAGE` mapping. Simple and reliable, but `CreateFileW` on system DLLs may be monitored by EDR.

**KnownDlls (OPSEC-friendly):** Open the `\KnownDlls\<dll>` section object using `NtOpenSection` + `NtMapViewOfSection`. These section objects are created by the kernel at boot time and contain pre-mapped copies of common system DLLs. This avoids filesystem I/O entirely — no `CreateFileW`, no disk reads, no filesystem event telemetry.

Both methods:
1. Parse the PE headers to locate the `.text` section
2. Overwrite the hooked in-memory `.text` with the pristine copy
3. All inline hooks are removed in a single operation

### Supported DLLs

| DLL | Commonly Hooked Functions |
|-----|--------------------------|
| ntdll.dll | NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx, NtOpenProcess |
| kernel32.dll | CreateProcessW, VirtualAlloc, WriteProcessMemory, CreateRemoteThread |
| kernelbase.dll | VirtualAlloc, ReadProcessMemory, CreateFileW |
| advapi32.dll | OpenProcessToken, AdjustTokenPrivileges, RegSetValueExW |
| user32.dll | SetWindowsHookExW, SendMessageW, PostMessageW |

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | unhook | `unhook` or `check` |
| dll | No | ntdll.dll | Target DLL: `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`, `advapi32.dll`, `user32.dll`, or `all` |
| source | No | disk | `disk` (read from System32) or `knowndlls` (use KnownDlls section objects — no disk I/O) |

## Usage

Unhook ntdll (default):
```
ntdll-unhook
```

Check for hooks on a specific DLL:
```
ntdll-unhook -action check -dll kernel32.dll
```

Unhook all four DLLs at once:
```
ntdll-unhook -action unhook -dll all
```

Check all DLLs for hooks:
```
ntdll-unhook -action check -dll all
```

Unhook using KnownDlls (OPSEC — no disk reads):
```
ntdll-unhook -dll all -source knowndlls
```

Unhook user32.dll specifically:
```
ntdll-unhook -dll user32.dll
```

## Example Output

### Unhook Single DLL
```
[*] ntdll.dll Unhooking
[*] In-memory base: 0x7FFC3E040000
[*] Clean copy mapped at: 0x1CE69590000
[*] .text section: RVA=0x1000, Size=1486848 bytes
[+] Restored 1486848 bytes of .text section
[+] ntdll.dll successfully unhooked — all inline hooks removed
```

### Unhook All
```
[*] ntdll.dll Unhooking
[*] .text section: RVA=0x1000, Size=1486848 bytes
[+] Restored 1486848 bytes of .text section
[+] ntdll.dll successfully unhooked — all inline hooks removed

[*] kernel32.dll Unhooking
[*] .text section: RVA=0x1000, Size=544768 bytes
[+] Restored 544768 bytes of .text section
[+] kernel32.dll successfully unhooked — all inline hooks removed

[*] kernelbase.dll Unhooking
[*] .text section: RVA=0x1000, Size=1720320 bytes
[+] Restored 1720320 bytes of .text section
[+] kernelbase.dll successfully unhooked — all inline hooks removed

[*] advapi32.dll Unhooking
[*] .text section: RVA=0x1000, Size=446464 bytes
[+] Restored 446464 bytes of .text section
[+] advapi32.dll successfully unhooked — all inline hooks removed
```

### Check (No Hooks)
```
[*] Checking ntdll.dll for inline hooks...
[+] No hooks detected — ntdll.dll .text section matches disk copy
[*] Compared 1486848 bytes
```

### Check (Hooks Detected)
```
[*] Checking ntdll.dll for inline hooks...
[!] Found 3 hooked regions in ntdll.dll .text section (1486848 bytes)

  0x7FFC3E041234 (5 bytes): 4C8BD1B8 → E94027FF
  0x7FFC3E042890 (5 bytes): 4C8BD1B8 → E98015FE
  0x7FFC3E043100 (5 bytes): 4C8BD1B8 → E9C00DFD

[*] Run 'ntdll-unhook -dll ntdll.dll' (action=unhook) to restore clean .text section
```

## Recommended Workflow

Run unhooking early in the engagement, before performing sensitive operations:

```
1. ntdll-unhook -action check -dll all   # See which DLLs are hooked
2. ntdll-unhook -dll all                  # Remove all hooks
3. ntdll-unhook -action check -dll all   # Verify hooks removed
4. hashdump / procdump / etc.            # Now safe from EDR interception
```

## MITRE ATT&CK Mapping

- T1562.001 — Impair Defenses: Disable or Modify Tools
