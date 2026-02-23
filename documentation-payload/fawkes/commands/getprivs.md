+++
title = "getprivs"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

List all privileges assigned to the current token (thread or process) with their enabled/disabled status and human-readable descriptions. Shows:

- Current identity (user and token source: process or impersonation)
- Integrity level (Untrusted, Low, Medium, High, System)
- Total privilege count and enabled count
- Each privilege with name, status, and description

This is useful for understanding what the current context can do before attempting privilege escalation or lateral movement. Key privileges to look for:

- **SeDebugPrivilege** — Required for `getsystem` and process injection into other users' processes
- **SeImpersonatePrivilege** — Required for `steal-token` and `make-token`
- **SeBackupPrivilege** — Can read any file regardless of ACLs
- **SeRestorePrivilege** — Can write any file regardless of ACLs
- **SeTcbPrivilege** — Act as part of the operating system

## Usage

```
getprivs
```

No parameters required. Works with both primary (process) tokens and impersonation (thread) tokens set by `make-token`, `steal-token`, or `getsystem`.

## Example Output

```
Token: WORKSTATION\user (Primary (process))
Integrity: High (S-1-16-12288)
Privileges: 24

Enabled: 24 / 24

PRIVILEGE                                     STATUS             DESCRIPTION
--------------------------------------------------------------------------------------------------------------
SeIncreaseQuotaPrivilege                      Enabled (Default)  Adjust memory quotas for a process
SeSecurityPrivilege                           Enabled (Default)  Manage auditing and security log
SeTakeOwnershipPrivilege                      Enabled (Default)  Take ownership of files or other objects
SeDebugPrivilege                              Enabled (Default)  Debug programs
SeImpersonatePrivilege                        Enabled (Default)  Impersonate a client after authentication
SeChangeNotifyPrivilege                       Enabled (Default)  Bypass traverse checking
...
```

## MITRE ATT&CK Mapping

- T1078 — Valid Accounts (privilege enumeration for access assessment)
