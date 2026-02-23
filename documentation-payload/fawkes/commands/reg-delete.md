+++
title = "reg-delete"
chapter = false
weight = 113
hidden = false
+++

## Summary

Delete registry keys or values from the Windows Registry. Supports deleting individual values, single keys, or entire key trees with recursive subkey deletion. Completes the registry operations suite alongside `reg-read` and `reg-write`.

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| hive | Yes | HKCU | Registry hive: `HKLM`, `HKCU`, `HKCR`, `HKU`, `HKCC` |
| path | Yes | - | Registry key path |
| name | No | - | Value name to delete (if empty, deletes the key itself) |
| recursive | No | false | Recursively delete all subkeys (only for key deletion) |

## Usage

### Delete a Value
```
reg-delete -hive HKCU -path "Software\TestKey" -name "TestValue"
```

### Delete a Key (Leaf Only)
```
reg-delete -hive HKCU -path "Software\TestKey"
```

### Delete a Key Tree (Recursive)
```
reg-delete -hive HKCU -path "Software\TestKey" -recursive true
```

### Cleanup Persistence Artifacts
```
reg-delete -hive HKCU -path "Software\Classes\ms-settings\Shell\Open\command" -recursive true
reg-delete -hive HKCU -path "Software\Classes\CLSID\{42aedc87-2188-41fd-b9a3-0c966feabec1}" -recursive true
```

## Example Output

### Delete Value
```
Deleted value: HKCU\Software\TestKey\TestValue
```

### Delete Key (Recursive)
```
  Deleted: Software\TestKey\Child1
  Deleted: Software\TestKey\Child2
  Deleted: Software\TestKey

Deleted HKCU\Software\TestKey (3 keys removed)
```

### Error — Key Has Subkeys
```
Error deleting key HKCU\Software\TestKey: Access is denied. (if key has subkeys, use -recursive true)
```

## Operational Notes

- **Value vs key deletion**: If `-name` is specified, only that value is deleted. If `-name` is empty, the entire key is deleted.
- **Non-recursive limitation**: `registry.DeleteKey` only works on leaf keys (keys without subkeys). For keys with children, use `-recursive true`.
- **Recursive deletion order**: Children are deleted depth-first (deepest keys first, then parents), matching how `registry.DeleteKey` works.
- **HKLM requires admin**: Deleting keys/values under `HKLM` requires administrator privileges. `HKCU` works at any privilege level.
- **Cleanup use cases**: Remove persistence artifacts (Run keys, COM hijacks, screensaver entries), clean up after UAC bypass, remove Defender exclusions.

## MITRE ATT&CK Mapping

- **T1112** — Modify Registry
