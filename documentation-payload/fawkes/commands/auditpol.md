+++
title = "auditpol"
chapter = false
weight = 155
hidden = false
+++

## Summary

Query and modify Windows audit policies to control security event logging. Disabling audit policies before sensitive operations prevents those operations from being logged in the Security event log, reducing forensic evidence.

Uses the `AuditQuerySystemPolicy`/`AuditSetSystemPolicy` API from advapi32.dll — no `auditpol.exe` process creation, reducing detection surface.

{{% notice info %}}Windows Only{{% /notice %}}

{{% notice warning %}}Requires administrative privileges (SeSecurityPrivilege){{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | query | Action: `query`, `disable`, `enable`, or `stealth` |
| category | No | | Category/subcategory name or `all`. Required for disable/enable |

### Actions

- **query** — Display current audit policy settings for all tracked subcategories
- **disable** — Disable auditing for specified category/subcategory (sets to "No Auditing")
- **enable** — Enable auditing for specified category/subcategory (sets to "Success and Failure")
- **stealth** — Disable the most detection-critical subcategories (Process Creation, Logon, Privilege Use, File System, Registry, Handle Manipulation)

### Supported Categories

| Category | Subcategories |
|----------|--------------|
| System | Security State Change, Security System Extension, System Integrity |
| Logon/Logoff | Logon, Logoff, Special Logon |
| Object Access | File System, Registry, Handle Manipulation |
| Privilege Use | Sensitive Privilege Use |
| Detailed Tracking | Process Creation, Process Termination |
| Policy Change | Audit Policy Change, Authentication Policy Change |
| Account Management | User Account Management, Security Group Management |
| DS Access | Directory Service Access, Directory Service Changes |
| Account Logon | Credential Validation, Kerberos Authentication Service, Kerberos Service Ticket Operations |

## Usage

```
# View current audit policies
auditpol -action query

# Disable all auditing
auditpol -action disable -category all

# Disable only process creation auditing
auditpol -action disable -category "Process Creation"

# Disable logon-related auditing
auditpol -action disable -category "Logon/Logoff"

# Stealth mode — disable detection-critical subcategories
auditpol -action stealth

# Re-enable all auditing after operations
auditpol -action enable -category all
```

## Output Format

The `query` action returns a JSON array rendered as a sortable table via browser script:
```json
[
  {
    "category": "Detailed Tracking",
    "subcategory": "Process Creation",
    "setting": "Success and Failure"
  }
]
```

The browser script highlights "No Auditing" settings in orange and "Success and Failure" in blue. Other actions (disable, enable, stealth) return plain text status messages.

## Operational Notes

- **Stealth mode** saves previous settings in the output — use this to manually restore after operations
- Changes take effect immediately — no reboot or service restart needed
- Audit policy changes are themselves logged (Event ID 4719) unless "Audit Policy Change" is disabled first
- Consider disabling "Audit Policy Change" first, then other categories, to avoid logging the changes

## MITRE ATT&CK Mapping

- **T1562.002** — Impair Defenses: Disable Windows Event Logging
