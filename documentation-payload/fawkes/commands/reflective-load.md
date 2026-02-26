+++
title = "reflective-load"
chapter = false
weight = 159
hidden = false
+++

## Summary

Load a native PE (DLL) from memory into the current process without writing to disk. Performs manual PE mapping: section copying, base relocation fixups, import resolution via LoadLibrary/GetProcAddress, and DllMain invocation. Optionally calls a named exported function after loading.

This is the native Windows counterpart to `inline-assembly` (.NET) and `inline-execute` (COFF/BOF) — it covers native DLLs that can't be loaded through those mechanisms.

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| dll_b64 | Yes | — | Base64-encoded PE/DLL file to load |
| function | No | — | Name of an exported function to call after loading (no-argument, returns uintptr) |

## Usage

```
# Load a DLL into the current process (calls DllMain automatically)
reflective-load -dll_b64 <base64_encoded_dll>

# Load a DLL and call a specific export
reflective-load -dll_b64 <base64_encoded_dll> -function RunPayload
```

## How It Works

1. **PE Parsing** — Validates MZ/PE signatures, reads NT headers, verifies x64 architecture
2. **Memory Allocation** — Allocates RW memory via VirtualAlloc for the full image size
3. **Section Mapping** — Copies PE headers and all sections to their virtual addresses
4. **Relocations** — Applies IMAGE_BASE_RELOCATION fixups (DIR64 type) for the load address delta
5. **Import Resolution** — Walks the Import Address Table, loads referenced DLLs via LoadLibraryA, resolves functions via GetProcAddress (supports import by name and ordinal)
6. **Section Protections** — Sets per-section memory protections (W^X: RX for code, RW for data, RO for read-only)
7. **Entry Point** — Calls DllMain(hModule, DLL_PROCESS_ATTACH, NULL) for DLL files
8. **Export Call** — Optionally calls a named export function

## Output

```
[*] Reflective PE Loader
[+] PE type: DLL, sections: 5, entry RVA: 0x1234
[+] Image size: 65536 bytes, preferred base: 0x180000000
[+] Allocated at 0x7FFE00000000 (size: 65536)
[+] Mapped 5 sections
[+] Processed 42 relocations (delta: 0x7FFE80000000)
[+] Resolved imports from 3 DLLs
[+] Set section protections
[*] Calling DllMain at 0x7FFE00001234...
[+] DllMain returned TRUE
[+] Reflective load complete
```

## Operational Notes

- **x64 only** — Only supports 64-bit PE files (IMAGE_FILE_MACHINE_AMD64)
- **Risk** — A malformed or incompatible DLL can crash the agent process. Test DLLs in a staging environment first
- **Memory footprint** — The loaded DLL remains in memory until the agent exits. Memory is freed if loading fails
- **W^X pattern** — Memory is allocated as RW, then per-section protections are applied after mapping. Code sections become RX (never RWX)
- **No TLS callbacks** — TLS directory callbacks are not currently invoked
- **Import resolution uses standard APIs** — LoadLibraryA/GetProcAddress are used for import resolution. These are subject to API monitoring. For stealth, pre-load required DLLs before reflective loading
- **Complements injection techniques** — Use this for in-process loading. For loading into remote processes, use `vanilla-inject`, `apc-inject`, `thread-hijack`, or other injection commands with shellcode generated from the DLL

## MITRE ATT&CK Mapping

- **T1620** — Reflective Code Loading
