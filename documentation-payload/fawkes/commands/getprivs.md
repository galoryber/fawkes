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

List, enable, disable, or strip token privileges. Supports:

- **list** — Show all privileges with enabled/disabled status and descriptions
- **enable** — Enable a specific privilege (e.g., SeDebugPrivilege)
- **disable** — Disable a specific privilege
- **strip** — Disable all non-essential privileges (keeps only SeChangeNotifyPrivilege)

The `strip` action reduces EDR detection surface by disabling privileges that trigger alerts (e.g., SeDebugPrivilege, SeImpersonatePrivilege). This makes the token appear less suspicious to behavioral analysis engines.

Key privileges:

- **SeDebugPrivilege** — Required for `getsystem` and process injection
- **SeImpersonatePrivilege** — Required for `steal-token` and `make-token`
- **SeBackupPrivilege** — Can read any file regardless of ACLs
- **SeRestorePrivilege** — Can write any file regardless of ACLs
- **SeTcbPrivilege** — Act as part of the operating system

## Arguments

| Argument  | Required | Default | Description |
|-----------|----------|---------|-------------|
| action    | Yes      | list    | `list`, `enable`, `disable`, or `strip` |
| privilege | No       | ""      | Privilege name (required for `enable`/`disable`) |

## Usage

### List privileges
```
getprivs
getprivs -action list
```

### Enable a privilege
```
getprivs -action enable -privilege SeDebugPrivilege
```

### Disable a privilege
```
getprivs -action disable -privilege SeDebugPrivilege
```

### Strip all non-essential privileges
```
getprivs -action strip
```

## MITRE ATT&CK Mapping

- T1134.002 — Access Token Manipulation: Create Process with Token
