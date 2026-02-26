+++
title = "hollow"
chapter = false
weight = 202
hidden = false
+++

{{% notice info %}}Windows Only{{% /notice %}}

## Summary

Process hollowing — create a suspended process and redirect its main thread to execute shellcode. Creates a new process in a suspended state, allocates memory, writes shellcode, updates the thread context (RCX register) to point to the shellcode, then resumes the thread.

Supports PPID spoofing to make the hollowed process appear as a child of a specified parent, and DLL blocking to prevent non-Microsoft DLLs from loading in the target process (useful for evading userland hooks).

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| filename | Yes (Default group) | Select shellcode from files registered in Mythic |
| file | Yes (New File group) | Upload a new shellcode file |
| shellcode_b64 | Yes (CLI group) | Base64-encoded raw shellcode bytes |
| target | No | Process to create and hollow (default: `C:\Windows\System32\svchost.exe`) |
| ppid | No | Parent PID to spoof (0 = no spoofing) |
| block_dlls | No | Block non-Microsoft DLLs from loading (default: false) |

## Usage

```
# From Mythic UI: select shellcode and configure target process
hollow -filename beacon.bin -target C:\Windows\System32\RuntimeBroker.exe

# With PPID spoofing and DLL blocking
hollow -filename beacon.bin -ppid 1234 -block_dlls true

# From API: provide base64-encoded shellcode
hollow -shellcode_b64 "kJBQ..." -target C:\Windows\System32\svchost.exe
```

## OPSEC Considerations

- Creates a new suspended process (CreateProcessW with CREATE_SUSPENDED)
- Uses extended startup info for PPID spoofing and DLL blocking attributes
- VirtualAllocEx with PAGE_READWRITE followed by VirtualProtect to PAGE_EXECUTE_READ
- SetThreadContext modifies the RCX register to redirect execution
- Cross-process memory write (WriteProcessMemory) may trigger EDR alerts
- If hollowing fails, the suspended process is terminated (TerminateProcess)
- Default target (svchost.exe) may require appropriate permissions

## MITRE ATT&CK Mapping

- **T1055.012** — Process Injection: Process Hollowing
