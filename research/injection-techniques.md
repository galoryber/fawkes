# Injection Technique Details

Detailed variant breakdowns for Fawkes injection commands. For usage, see the main [README](../README.md).

## PoolParty Injection

PoolParty injection abuses Windows Thread Pool internals to achieve code execution without calling monitored APIs like `CreateRemoteThread`. All 8 variants from the SafeBreach Labs research are implemented:

| Variant | Technique | Trigger Mechanism | Go Shellcode |
|---------|-----------|-------------------|--------------|
| 1 | Worker Factory Start Routine Overwrite | New worker thread creation | No |
| 2 | TP_WORK Insertion | Task queue processing | Yes |
| 3 | TP_WAIT Insertion | Event signaling | Yes |
| 4 | TP_IO Insertion | File I/O completion | Yes |
| 5 | TP_ALPC Insertion | ALPC port messaging | Yes |
| 6 | TP_JOB Insertion | Job object assignment | Yes |
| 7 | TP_DIRECT Insertion | I/O completion port | Yes |
| 8 | TP_TIMER Insertion | Timer expiration | Yes |

**Go Shellcode Compatibility:** Variant 1 executes shellcode as a thread's start routine (early initialization context) which doesn't meet Go runtime requirements (TLS, scheduler state). Variants 2-8 use callback mechanisms on fully-initialized threads, making them compatible with Go shellcode. Simple shellcode (calc.bin) works with all variants.

### Variant Details

- **Variant 1** - Overwrites the worker factory start routine. Triggers when new thread pool workers are created via NtSetInformationWorkerFactory.
- **Variant 2** - Inserts a TP_WORK item into the high-priority task queue. Executes when thread pool processes work items.
- **Variant 3** - Creates a TP_WAIT structure and associates an event with the target's I/O completion port. Triggers via SetEvent.
- **Variant 4** - Creates a TP_IO structure and associates a file with the target's I/O completion port. Triggers via async file write.
- **Variant 5** - Creates a TP_ALPC structure and associates an ALPC port with the target's I/O completion port. Triggers via NtAlpcConnectPort.
- **Variant 6** - Creates a TP_JOB structure and associates a job object with the target's I/O completion port. Triggers via AssignProcessToJobObject.
- **Variant 7** - Inserts a TP_DIRECT structure and triggers via ZwSetIoCompletion. Simplest I/O completion variant.
- **Variant 8** - Inserts a TP_TIMER into the timer queue and triggers via NtSetTimer2. Uses timer queue instead of I/O completion.

## Opus Injection

Opus injection uses callback-based injection techniques to achieve code execution through manipulation of Windows callback tables and handler chains.

| Variant | Technique | Target | Go Shellcode Compatible |
|---------|-----------|--------|------------------------|
| 1 | Ctrl-C Handler Chain | Console processes only | No |
| 4 | PEB KernelCallbackTable | GUI processes only | Yes |

### Variant 1 - Ctrl-C Handler Chain

- **How it works:** Injects a fake handler into the target's console Ctrl+C handler array (in kernelbase.dll), then triggers a Ctrl+C event. Windows decodes and calls our shellcode as part of normal handler dispatch.
- **Target limitation:** Console processes only (cmd.exe, powershell.exe, etc.)
- **Go-based Shellcode:** Not compatible - Ctrl+C handler context conflicts with Go runtime expectations
- **Detection Surface:** WriteProcessMemory/VirtualAllocEx (standard) + AttachConsole/GenerateConsoleCtrlEvent (uncommon). No CreateRemoteThread, no APC.

### Variant 4 - PEB KernelCallbackTable

- **How it works:** Modifies the PEB KernelCallbackTable pointer to redirect win32k user-mode callbacks (specifically `__fnCOPYDATA`). Triggers execution by sending a WM_COPYDATA window message.
- **Target limitation:** GUI processes only (notepad.exe, explorer.exe, any process with user32.dll loaded and visible windows)
- **Go-based Shellcode:** Compatible! WM_COPYDATA callback context works with Go's runtime requirements
- **Detection Surface:** WriteProcessMemory/VirtualAllocEx (standard) + NtQueryInformationProcess (common) + PEB modification + SendMessage (IPC - normal behavior). No CreateRemoteThread, no APC, no thread pool manipulation.
- **Multi-agent operation:** Both the injector agent and injected agent can operate simultaneously. The trigger is sent asynchronously to prevent blocking the injector.
