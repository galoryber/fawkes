+++
title = "reg-write"
chapter = false
weight = 105
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Write a value to the Windows Registry. Creates the key and value if they don't already exist. Supports REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, and REG_BINARY value types.

### Arguments

#### hive (required)
Registry hive to write to. Choose one of: `HKLM`, `HKCU`, `HKCR`, `HKU`, `HKCC`.

#### path (required)
Registry key path (will be created if it doesn't exist).

#### name (optional)
Value name to write. Leave empty to write the default value.

#### data (required)
Data to write. For REG_DWORD/REG_QWORD, use a decimal number. For REG_BINARY, use a hex string (e.g., `0102ff`).

#### type (required)
Registry value type. Choose one of: `REG_SZ`, `REG_EXPAND_SZ`, `REG_DWORD`, `REG_QWORD`, `REG_BINARY`.

## Usage
```
reg-write -hive HKCU -path "Software\TestKey" -name "TestValue" -data "hello" -type REG_SZ
reg-write -hive HKCU -path "Software\TestKey" -name "Counter" -data "42" -type REG_DWORD
reg-write -hive HKCU -path "Software\TestKey" -name "Binary" -data "deadbeef" -type REG_BINARY
```

## MITRE ATT&CK Mapping

- T1112 — Modify Registry
