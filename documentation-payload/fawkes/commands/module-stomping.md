+++
title = "module-stomping"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Inject shellcode by loading a sacrificial DLL into the target process and overwriting its `.text` section. The shellcode executes from within a signed Microsoft DLL's address space, defeating private-memory detection heuristics used by EDR/AV memory scanners.

Unlike standard injection techniques that allocate new private executable memory (which memory scanners flag), module stomping places shellcode at an address backed by a legitimate, signed DLL. Simple memory scanners that only check for private `PAGE_EXECUTE_READ` regions will miss it.

When indirect syscalls are enabled (build parameter), core APIs use Nt* indirect stubs:
- LoadLibraryW thread: NtCreateThreadEx (with argument)
- Memory operations: NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory
- Process/handle: NtOpenProcess, NtClose
- PE parsing: NtReadVirtualMemory

Memory follows W^X pattern (protect RW, write shellcode, protect RX).

### How It Works

1. **Open target process** with required access rights
2. **Write DLL path** to remote process memory (UTF-16)
3. **Load sacrificial DLL** via CreateRemoteThread/NtCreateThreadEx calling LoadLibraryW
4. **Find loaded DLL** base via CreateToolhelp32Snapshot module enumeration
5. **Parse PE headers** remotely to locate the `.text` section
6. **Verify fit** — shellcode must be smaller than `.text` section
7. **Stomp `.text`** — VirtualProtect to RW, write shellcode, protect to RX
8. **Execute** — CreateRemoteThread/NtCreateThreadEx at `.text` base address

### Arguments

#### Shellcode File
Select a shellcode file already registered in Mythic, or upload a new shellcode file. For API/CLI usage, provide base64-encoded shellcode via the `shellcode_b64` parameter.

#### Target PID
The process ID to inject shellcode into.

#### Sacrificial DLL
The DLL to load from `C:\Windows\System32` and overwrite (default: `xpsservices.dll`). The DLL's `.text` section must be larger than the shellcode. Good candidates:
- **xpsservices.dll** (default) — XPS Services, ~1.8 MB .text, rarely loaded
- **msftedit.dll** — Rich Text Editor, ~2.6 MB .text, rarely loaded
- Any System32 DLL with a large `.text` section that isn't commonly loaded

## Usage

Use the Mythic UI popup to select shellcode, target PID, and optionally a different sacrificial DLL.

```
# Via API/CLI with base64 shellcode
module-stomping -shellcode_b64 <base64> -pid 1234

# With custom sacrificial DLL
module-stomping -shellcode_b64 <base64> -pid 1234 -dll_name msftedit.dll
```

## Opsec Considerations

- Shellcode address maps to a signed Microsoft DLL on disk
- No new private executable memory allocation (avoids PAGE_EXECUTE_READ private heuristic)
- LoadLibraryW call is detectable but standard Windows behavior
- Deep memory scanners comparing disk vs memory content can detect the modified `.text`
- Using indirect syscalls hides the NtCreateThreadEx / NtWriteVirtualMemory API calls

## MITRE ATT&CK Mapping

- T1055.001 — Process Injection: Dynamic-link Library Injection
