+++
title = "modules"
chapter = false
weight = 118
hidden = false
+++

## Summary

List loaded modules, DLLs, and shared libraries in a process. Useful for injection reconnaissance (identifying target DLLs and base addresses), EDR detection (spotting security-related DLLs), and general process analysis.

Cross-platform — works on Windows, Linux, and macOS.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| pid | No | current process | Target process ID to enumerate |

## Usage

```
# List modules for current process (agent)
modules

# List modules for a specific process
modules -pid 1234

# Find loaded DLLs in a target process (Windows)
modules -pid 4852
```

### Browser Script

Output is rendered as a sortable table in the Mythic UI with columns: Base Address, Size, Name, Path. Key system DLLs (ntdll.dll, kernel32.dll, kernelbase.dll) are highlighted blue. Size is formatted as KB/MB in the browser script.

### Example Output (JSON)
```json
[
  {"name":"ntdll.dll","path":"C:\\WINDOWS\\SYSTEM32\\ntdll.dll","base_addr":"0x7FFC466F0000","size":2097152},
  {"name":"KERNEL32.DLL","path":"C:\\WINDOWS\\System32\\KERNEL32.DLL","base_addr":"0x7FFC46180000","size":757760}
]
```

{{% notice note %}}
Statically-linked Go binaries (like Fawkes) on Linux may only show the binary itself. Dynamically-linked processes will show all loaded shared libraries (libc, ld-linux, etc.).
{{% /notice %}}

## Platform Implementation

| Platform | Method | Notes |
|----------|--------|-------|
| **Windows** | `CreateToolhelp32Snapshot` + `Module32FirstW/NextW` | Lists all loaded DLLs with base addresses and sizes. Works for any accessible process. |
| **Linux** | `/proc/[pid]/maps` parsing | Aggregates memory-mapped regions by path. Shows shared libraries and the main binary. |
| **macOS** | `proc_info` syscall (SYS_PROC_INFO=336) | Iterates memory regions via PROC_PIDREGIONINFO + PROC_PIDREGIONPATHINFO2. Requires same-user or root for other processes. |

## Use Cases

1. **Injection Reconnaissance**: Before injecting into a process, check which DLLs are loaded and their base addresses.
2. **EDR Detection**: Look for security-related DLLs (e.g., `amsi.dll`, `clrjit.dll`, EDR hooks in `ntdll.dll`).
3. **Process Analysis**: Understand what a process has loaded for troubleshooting or intelligence gathering.
4. **DLL Hijacking**: Identify which DLLs a process loads to find hijacking opportunities.

## OPSEC

- **Windows**: Uses `CreateToolhelp32Snapshot` — a common, legitimate API call. Low detection risk.
- **Linux**: Reads `/proc/[pid]/maps` — a standard filesystem read. No suspicious API calls.
- **macOS**: Uses `proc_info` syscall — standard macOS process introspection.
- No process injection or memory writes. Read-only operation.

## MITRE ATT&CK Mapping

- **T1057** — Process Discovery
