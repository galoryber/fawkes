+++
title = "vanilla-injection"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Inject shellcode into a remote process using the classic VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread technique, or **migrate the agent** into another process (inject + exit). This is the most straightforward injection method but also the most commonly monitored.

### Actions

| Action | Description |
|--------|-------------|
| `inject` | Inject shellcode into target process (default). The current agent continues running. |
| `migrate` | Inject agent shellcode into target process and exit the current process. A new callback appears from the target process while the original callback goes offline. |

### Arguments

#### Action
Choose `inject` (default) to inject shellcode, or `migrate` to perform process migration (inject + exit).

#### Shellcode File
Select a shellcode file already registered in Mythic, or upload a new shellcode file. For migration, build a Fawkes payload in `windows-shellcode` mode and use that file.

#### Target PID
The process ID to inject shellcode into. For migration, choose a stable, long-lived process (e.g., `explorer.exe`, `svchost.exe`).

## Usage

### Standard Injection
Use the Mythic UI popup to select shellcode and enter the target PID. Action defaults to `inject`.

### Process Migration
1. Build a Fawkes payload with **windows-shellcode** build mode (produces position-independent shellcode via sRDI)
2. Use `vanilla-injection` with action set to **migrate**
3. Select the shellcode file and target PID
4. The current agent injects the shellcode, sends a confirmation response, then exits after 5 seconds
5. A new callback will appear from the target process

{{% notice warning %}}
Migration terminates the current callback. Ensure the shellcode payload is valid and the target process is stable before migrating. If injection fails, the current agent remains running.
{{% /notice %}}

## MITRE ATT&CK Mapping

- T1055.001 — Process Injection: Dynamic-link Library Injection
- T1055.002 — Process Injection: Portable Executable Injection
