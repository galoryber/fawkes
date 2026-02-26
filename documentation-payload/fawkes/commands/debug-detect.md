+++
title = "debug-detect"
chapter = false
weight = 170
hidden = false
+++

## Summary

Detect attached debuggers, analysis tools, and instrumentation. Runs multiple platform-specific checks and scans for known debugger processes to determine if the agent is being analyzed.

## Platform Checks

### Windows (6 checks)
| Check | Method | Detects |
|-------|--------|---------|
| IsDebuggerPresent | kernel32 API | User-mode debugger attached to process |
| CheckRemoteDebuggerPresent | kernel32 API | Remote debugger via debug port |
| NtQuery (DebugPort) | NtQueryInformationProcess (class 7) | Kernel debug port (non-zero = debugged) |
| NtQuery (DebugObjectHandle) | NtQueryInformationProcess (class 30) | Debug object handle existence |
| PEB.BeingDebugged | Read PEB offset 0x2 | PEB flag set by ntdll!LdrpInitialize |
| Hardware Breakpoints (DR0-3) | GetThreadContext | Debug registers set by analyst |

### Linux (2 checks)
| Check | Method | Detects |
|-------|--------|---------|
| TracerPid | /proc/self/status | ptrace-attached debugger (GDB, strace, ltrace) |
| LD_PRELOAD | Environment variable | Library injection/hooking |

### macOS (2 checks)
| Check | Method | Detects |
|-------|--------|---------|
| sysctl P_TRACED | kern.proc.pid sysctl | Debugger attached via ptrace |
| DYLD_INSERT_LIBRARIES | Environment variable | Library injection |

### Cross-Platform (1 check)
| Check | Method | Detects |
|-------|--------|---------|
| Debugger Process Scan | Process enumeration | 50+ known debuggers/analysis tools (WinDbg, x64dbg, IDA, GDB, lldb, Ghidra, Process Hacker, Wireshark, etc.) |

## Arguments

None. All checks run automatically.

## Usage

```
debug-detect
```

## Output

```
Debug Detection Results
=======================

     IsDebuggerPresent                   CLEAN      Not detected
     CheckRemoteDebuggerPresent          CLEAN      Not detected
     NtQuery (DebugPort)                 CLEAN      Debug port: 0
     NtQuery (DebugObjectHandle)         CLEAN      No debug object
     PEB.BeingDebugged                   CLEAN      Flag: 0
     Hardware Breakpoints (DR0-3)        CLEAN      All DR registers clear
     Debugger Process Scan               CLEAN      No known debugger processes found

[+] All checks CLEAN — no debugger/analysis activity detected
```

## MITRE ATT&CK Mapping

- T1497.001 — Virtualization/Sandbox Evasion: System Checks
