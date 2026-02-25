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

Remove EDR (Endpoint Detection and Response) inline hooks from `ntdll.dll` by reading a clean copy from disk and overwriting the in-memory `.text` section. Also supports checking for hooks without removing them.

### How EDR Hooking Works

EDR products inject monitoring DLLs into every user-mode process. These DLLs overwrite the first few bytes of key ntdll functions (e.g., `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`) with `JMP` instructions that redirect to the EDR's inspection trampoline. This allows the EDR to inspect all syscall arguments before they reach the kernel.

### How Unhooking Works

Since the on-disk `ntdll.dll` is never modified (it's the original Microsoft-signed binary), we can:

1. Map a clean copy of `ntdll.dll` from `C:\Windows\System32\ntdll.dll` using `SEC_IMAGE` (PE section alignment)
2. Parse the PE headers to locate the `.text` section
3. Overwrite the hooked in-memory `.text` with the pristine disk copy
4. All inline hooks are removed in a single operation

### Actions

- **unhook** (default) — Replace the hooked `.text` section with a clean copy from disk
- **check** — Compare in-memory vs disk `.text` section and report any differences (potential hooks)

### Arguments

#### action
The operation to perform. Default: `unhook`.
- `unhook` — Restore clean .text section (removes all hooks)
- `check` — Report hooked regions without modifying memory

## Usage

Unhook ntdll (default):
```
ntdll-unhook
```

Check for hooks first:
```
ntdll-unhook -action check
```

Unhook explicitly:
```
ntdll-unhook -action unhook
```

## Example Output

### Unhook
```
[*] ntdll.dll Unhooking
[*] In-memory ntdll base: 0x7FFC3E040000
[*] Clean ntdll mapped at: 0x1CE69590000
[*] .text section: RVA=0x1000, Size=1486848 bytes
[+] Restored 1486848 bytes of .text section
[+] ntdll.dll successfully unhooked — all inline hooks removed
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
[!] Found 3 hooked regions in .text section (1486848 bytes)

  0x7FFC3E041234 (5 bytes): 4C8BD1B8 → E94027FF
  0x7FFC3E042890 (5 bytes): 4C8BD1B8 → E98015FE
  0x7FFC3E043100 (5 bytes): 4C8BD1B8 → E9C00DFD

[*] Run 'ntdll-unhook' (action=unhook) to restore clean .text section
```

## Recommended Workflow

Run unhooking early in the engagement, before performing sensitive operations:

```
1. ntdll-unhook -action check     # See if hooks exist
2. ntdll-unhook                    # Remove hooks
3. ntdll-unhook -action check     # Verify hooks removed
4. hashdump / procdump / etc.     # Now safe from EDR interception
```

## MITRE ATT&CK Mapping

- T1562.001 — Impair Defenses: Disable or Modify Tools
