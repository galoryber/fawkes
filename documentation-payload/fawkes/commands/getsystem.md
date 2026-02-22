+++
title = "getsystem"
chapter = false
weight = 104
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Elevate to SYSTEM by automatically finding and stealing a token from a SYSTEM process. This is a convenience wrapper that:

1. Enables SeDebugPrivilege on the current process
2. Enumerates running processes to find one running as NT AUTHORITY\SYSTEM
3. Opens the process token, duplicates it, and impersonates it

Preferred SYSTEM processes (in order): winlogon.exe, lsass.exe, services.exe, svchost.exe. Falls back to any SYSTEM process if preferred ones are inaccessible.

Requires administrator privileges (specifically SeDebugPrivilege) to open tokens from SYSTEM processes. Use `rev2self` to revert to the original context.

### Arguments

#### technique
Escalation technique to use. Currently supported: `steal` (default). Auto-discovers a SYSTEM process and steals its token.

## Usage

```
getsystem
```

Or explicitly specifying the technique:
```
getsystem -technique steal
```

## Example Output

```
Successfully elevated to SYSTEM
Technique: Token steal from winlogon.exe (PID 860)
Old: WORKSTATION\user
New: NT AUTHORITY\SYSTEM
Use rev2self to revert to original context
```

## MITRE ATT&CK Mapping

- T1134.001 — Access Token Manipulation: Token Impersonation/Theft
