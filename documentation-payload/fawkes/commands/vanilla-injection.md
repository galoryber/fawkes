+++
title = "vanilla-injection"
chapter = false
weight = 103
hidden = false
+++

## Summary

Inject shellcode into a remote process or **migrate the agent** into another process (inject + exit).

**Windows:** Uses VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread (or indirect syscalls via ntdll). Supports auto-target selection scoring processes for EDR avoidance.

**Linux:** Uses ptrace attach + /proc/PID/mem direct write. Avoids PTRACE_POKETEXT which is monitored by some EDR products. Allocates memory via remote mmap syscall, writes shellcode through the /proc/mem pseudo-file, then redirects RIP.

### Actions

| Action | Description |
|--------|-------------|
| `inject` | Inject shellcode into target process (default). The current agent continues running. |
| `migrate` | Inject agent shellcode into target process and exit the current process. A new callback appears from the target process while the original callback goes offline. |

### Arguments

#### Action
Choose `inject` (default) to inject shellcode, or `migrate` to perform process migration (inject + exit).

#### Shellcode File
Select a shellcode file already registered in Mythic, or upload a new shellcode file.

#### Target PID
The process ID to inject shellcode into. For migration, choose a stable, long-lived process.

## Usage

### Standard Injection
Use the Mythic UI popup to select shellcode and enter the target PID.

### Process Migration
1. Build a Fawkes payload in shellcode mode for the target platform
2. Use `vanilla-injection` with action set to **migrate**
3. Select the shellcode file and target PID
4. The current agent injects the shellcode, sends a confirmation response, then exits after 5 seconds
5. A new callback will appear from the target process

### Linux Notes
- Requires ptrace capability (check with `ptrace-inject -action check`)
- Yama LSM ptrace_scope must be 0 (classic) or agent must have CAP_SYS_PTRACE
- Target must be same-UID or agent must be root

{{% notice warning %}}
Migration terminates the current callback. Ensure the shellcode payload is valid and the target process is stable before migrating.
{{% /notice %}}

## MITRE ATT&CK Mapping

- T1055.001 — Process Injection: Dynamic-link Library Injection (Windows)
- T1055.002 — Process Injection: Portable Executable Injection (Windows)
- T1055.009 — Process Injection: Proc Memory (Linux)
