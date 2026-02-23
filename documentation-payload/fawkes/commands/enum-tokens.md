+++
title = "enum-tokens"
chapter = false
weight = 102
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Enumerate access tokens across all accessible processes on the system. Shows which users have active processes, their integrity levels, and session IDs. This is essential for planning lateral movement via `steal-token` — it answers "which process should I steal a token from?"

Auto-enables SeDebugPrivilege for maximum visibility into other users' processes. Processes that cannot be opened (e.g., kernel-protected) show as "(access denied)".

## Arguments

### action
- `list` (default) — Show all process tokens in a table: PID, process name, user, integrity level, session ID
- `unique` — Show unique token owners grouped with process counts, session list, and example process names

### user
Optional case-insensitive substring filter. Only show tokens matching this user string.

## Usage

List all process tokens:
```
enum-tokens
```

Show unique users with process counts:
```
enum-tokens -action unique
```

Filter to SYSTEM tokens only:
```
enum-tokens -action list -user SYSTEM
```

Filter to a specific user:
```
enum-tokens -action unique -user setup
```

## Example Output

### List Action

```
Tokens enumerated: 141 processes

PID      PROCESS                        USER                                INTEGRITY  SESSION
-----------------------------------------------------------------------------------------------
4        System                         NT AUTHORITY\SYSTEM                 System     0
112      Registry                       NT AUTHORITY\SYSTEM                 System     0
672      svchost.exe                    NT AUTHORITY\SYSTEM                 System     0
856      svchost.exe                    NT AUTHORITY\LOCAL SERVICE          System     0
5644     fontdrvhost.exe                Font Driver Host\UMFD-2             Low        2
...
```

### Unique Action

```
Unique token owners: 9

USER                                INTEGRITY  PROCS    SESSIONS   EXAMPLE PROCESSES
--------------------------------------------------------------------------------------------------------------
NT AUTHORITY\LOCAL SERVICE          System     26       0          svchost.exe, WmiPrvSE.exe, NisSrv.exe
NT AUTHORITY\NETWORK SERVICE        System     6        0          svchost.exe
NT AUTHORITY\SYSTEM                 System     63       0,2        System, Registry, smss.exe, csrss.exe
Win1123H2\setup                     High       42       0,2        sihost.exe, explorer.exe, ShellHost.exe
...
```

## MITRE ATT&CK Mapping

- T1134 — Access Token Manipulation (token enumeration for steal-token planning)
- T1057 — Process Discovery (cross-process enumeration)
