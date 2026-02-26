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

## Example Output (Windows)

```
Modules loaded in PID 4852 (19 total):

Base Address       Size         Name                                     Path
------------------------------------------------------------------------------------------------------------------------
0x7FF772530000     18.9 MB      fawkes_modules.exe                       C:\Users\setup\Downloads\fawkes_modules.exe
0x7FFC32910000     140.0 KB     dhcpcsvc.DLL                             C:\WINDOWS\SYSTEM32\dhcpcsvc.DLL
0x7FFC334C0000     120.0 KB     dhcpcsvc6.DLL                            C:\WINDOWS\SYSTEM32\dhcpcsvc6.DLL
0x7FFC3A3A0000     32.0 KB      winrnr.dll                               C:\WINDOWS\system32\winrnr.dll
0x7FFC44980000     796.0 KB     msvcrt.dll                               C:\WINDOWS\System32\msvcrt.dll
0x7FFC45910000     2.1 MB       KERNELBASE.dll                           C:\WINDOWS\System32\KERNELBASE.dll
0x7FFC46180000     740.0 KB     KERNEL32.DLL                             C:\WINDOWS\System32\KERNEL32.DLL
0x7FFC466F0000     2.0 MB       ntdll.dll                                C:\WINDOWS\SYSTEM32\ntdll.dll
...
```

## Example Output (Linux)

```
Modules loaded in PID 55425 (1 total):

Base Address       Size         Name                                     Path
------------------------------------------------------------------------------------------------------------------------
0x400000           13.5 MB      fawkes_mod2                              /tmp/fawkes_mod2
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
