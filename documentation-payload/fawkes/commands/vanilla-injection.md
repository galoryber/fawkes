+++
title = "vanilla-injection"
chapter = false
weight = 103
hidden = false
+++

## Summary

Inject shellcode into a remote process or **migrate the agent** into another process (inject + exit).

**Windows:** Uses VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread (or indirect syscalls via ntdll). Supports auto-target selection scoring processes for EDR avoidance.

**Linux (amd64/arm64):** Uses ptrace attach + /proc/PID/mem direct write. Avoids PTRACE_POKETEXT which is monitored by some EDR products. Allocates memory via remote mmap syscall, writes shellcode through the /proc/mem pseudo-file, then redirects execution (RIP on amd64, PC on arm64). Yama ptrace_scope is checked before attach with actionable guidance.

**Linux LD_PRELOAD (amd64/arm64):** Builds a minimal ELF shared library with DT_INIT pointing to the shellcode, writes it to an anonymous memfd (fileless), and spawns a target process with `LD_PRELOAD` pointing to the memfd. No ptrace required — works under Yama ptrace_scope=1+.

### Actions

| Action | Description |
|--------|-------------|
| `inject` | Inject shellcode into target process (default). The current agent continues running. |
| `migrate` | Inject agent shellcode into target process and exit the current process. A new callback appears from the target process while the original callback goes offline. |
| `ldpreload` | Linux-only. Spawn a new process with LD_PRELOAD set to a memfd-backed .so containing the shellcode. No ptrace needed. Use `-target` to specify the host process (default: `/usr/bin/id`). |

### Arguments

#### Action
Choose `inject` (default) to inject shellcode, or `migrate` to perform process migration (inject + exit).

#### Shellcode File
Select a shellcode file already registered in Mythic, or upload a new shellcode file.

#### Target PID
The process ID to inject shellcode into. For migration, choose a stable, long-lived process.

#### Stack Spoof (`stack_spoof`)
Spoof the call stack during injection API calls. Executes Nt* syscalls from a dedicated thread with fake kernel32/ntdll return frames, evading EDR thread stack scanners. Requires `indirect_syscalls` and `stack_spoof` build options. Default: `false`.

## Usage

### Standard Injection
Use the Mythic UI popup to select shellcode and enter the target PID.

### Process Migration
1. Build a Fawkes payload in shellcode mode for the target platform
2. Use `vanilla-injection` with action set to **migrate**
3. Select the shellcode file and target PID
4. The current agent injects the shellcode, sends a confirmation response, then exits after 5 seconds
5. A new callback will appear from the target process

### Linux Notes (inject/migrate)
- Requires ptrace capability (check with `ptrace-inject -action check`)
- Yama LSM ptrace_scope must be 0 (classic) or agent must have CAP_SYS_PTRACE
- Target must be same-UID or agent must be root

### Linux Notes (ldpreload)
- No ptrace required — works under Yama ptrace_scope=1, 2, or 3
- Shellcode executes as DT_INIT constructor before the host process's main()
- Shellcode should fork/thread if the host process needs to continue
- The .so is written to an anonymous memfd (no file on disk)
- `/proc/PID/maps` will show a `(deleted)` memfd entry

{{% notice warning %}}
Migration terminates the current callback. Ensure the shellcode payload is valid and the target process is stable before migrating.
{{% /notice %}}

## MITRE ATT&CK Mapping

- T1055.001 — Process Injection: Dynamic-link Library Injection (Windows)
- T1055.002 — Process Injection: Portable Executable Injection (Windows)
- T1055.009 — Process Injection: Proc Memory (Linux)
- T1574.006 — Hijack Execution Flow: Dynamic Linker Hijacking (Linux LD_PRELOAD)
