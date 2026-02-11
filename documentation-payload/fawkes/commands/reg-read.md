+++
title = "reg-read"
chapter = false
weight = 104
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Read a value from the Windows Registry. Supports all standard registry hives (HKLM, HKCU, HKCR, HKU, HKCC) and value types (REG_SZ, REG_DWORD, REG_BINARY, REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD).

If no value name is specified, enumerates all values and subkeys under the given key.

### Arguments

#### hive (required)
Registry hive to read from. Choose one of: `HKLM`, `HKCU`, `HKCR`, `HKU`, `HKCC`.

#### path (required)
Registry key path (e.g., `SOFTWARE\Microsoft\Windows\CurrentVersion`).

#### name (optional)
Value name to read. Leave empty to enumerate all values and subkeys under the key.

## Usage
```
reg-read -hive HKLM -path "SOFTWARE\Microsoft\Windows\CurrentVersion" -name "ProgramFilesDir"
reg-read -hive HKCU -path "Environment"
reg-read -hive HKLM -path "SOFTWARE\Microsoft\Windows\CurrentVersion"
```

## MITRE ATT&CK Mapping

- T1012 — Query Registry
