+++
title = "spawn"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Spawn a suspended process or create a suspended thread in an existing process. Useful for preparing targets for injection techniques like `apc-injection`.

Supports two opsec features for process mode:
- **PPID Spoofing** — Make the spawned process appear as a child of any process (e.g., explorer.exe) to evade parent-child relationship detection.
- **Block Non-Microsoft DLLs** — Prevent third-party DLLs (including most EDR hooking DLLs) from loading in the spawned process.

### Arguments

#### Executable Path
Path to the executable to spawn suspended. Default: `C:\Windows\System32\notepad.exe`.

#### Target PID (Thread Mode)
Process ID to create a suspended thread in. If set to a value > 0, thread mode is used instead of process mode.

#### Parent PID (PPID Spoofing)
Spoof the parent process ID. Set to the PID of a process like explorer.exe so the spawned process appears as its child in Task Manager and EDR telemetry. Process mode only. Default: 0 (no spoofing).

#### Block Non-MS DLLs
When enabled, applies `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` to the spawned process. This prevents most EDR user-mode hooking DLLs from injecting. Process mode only. Default: false.

## Usage

Basic spawn (suspended notepad):
```
spawn -path C:\Windows\System32\notepad.exe
```

Spawn with PPID spoofing (appears as child of explorer.exe PID 1234):
```
spawn -path C:\Windows\System32\notepad.exe -ppid 1234
```

Spawn with DLL blocking (prevents EDR hooks):
```
spawn -path C:\Windows\System32\notepad.exe -blockdlls true
```

Combined PPID spoofing + DLL blocking:
```
spawn -path C:\Windows\System32\notepad.exe -ppid 1234 -blockdlls true
```

Typical injection workflow:
```
spawn -path notepad.exe -ppid 1234 -blockdlls true
apc-injection    (inject shellcode via APC into the suspended process)
```

## MITRE ATT&CK Mapping

- T1055 — Process Injection
- T1134.004 — Access Token Manipulation: Parent PID Spoofing
