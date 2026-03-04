+++
title = "reg"
chapter = false
weight = 200
hidden = false
+++

## Summary

Unified Windows Registry operations — read, write, delete, search, and save hives in a single command.

{{% notice info %}}Windows Only{{% /notice %}}

This command provides a single entry point for all registry operations. The individual commands (`reg-read`, `reg-write`, `reg-delete`, `reg-search`, `reg-save`) remain available as aliases.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | read | `read`, `write`, `delete`, `search`, `save`, or `creds` |
| hive | No | HKLM | Registry hive (HKLM, HKCU, HKCR, HKU, HKCC) |
| path | Varies | — | Registry key path |
| name | No | — | Value name (for read/write/delete) |
| data | No | — | Data to write (for write action) |
| reg_type | No | REG_SZ | Value type: REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_BINARY |
| recursive | No | false | Recursively delete subkeys (for delete action) |
| pattern | No | — | Search pattern (for search action) |
| max_depth | No | 5 | Max recursion depth (for search action) |
| max_results | No | 50 | Max results (for search action) |
| output | No | — | Output file path (for save action) |

## Usage

### Read a specific value
```
reg -action read -hive HKLM -path "SOFTWARE\Microsoft\Windows\CurrentVersion" -name ProgramFilesDir
```

### Enumerate all values under a key
```
reg -action read -hive HKLM -path "SOFTWARE\Microsoft\Windows\CurrentVersion"
```

### Write a registry value
```
reg -action write -hive HKCU -path "Software\TestKey" -name MyValue -data "hello" -type REG_SZ
reg -action write -hive HKCU -path "Software\TestKey" -name Counter -data 42 -type REG_DWORD
```

### Delete a value or key
```
reg -action delete -hive HKCU -path "Software\TestKey" -name MyValue
reg -action delete -hive HKCU -path "Software\TestKey" -recursive true
```

### Search the registry
```
reg -action search -pattern "password" -hive HKLM -path SOFTWARE -max_depth 5
```

### Export hives for offline credential extraction
```
reg -action save -hive HKLM -path SAM -output C:\Temp\sam.hiv
reg -action creds
```

## MITRE ATT&CK Mapping

- **T1012** — Query Registry
- **T1112** — Modify Registry
- **T1003.002** — Security Account Manager (SAM)
