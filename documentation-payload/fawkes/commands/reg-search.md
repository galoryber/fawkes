+++
title = "reg-search"
chapter = false
weight = 120
hidden = false
+++

## Summary

Recursively searches Windows Registry keys, value names, and value data for a case-insensitive pattern. Useful for discovering configuration settings, installed software, persistence mechanisms, and credentials stored in the registry.

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| pattern | Yes | | Case-insensitive search pattern to match against key names, value names, and value data |
| hive | No | HKLM | Registry hive to search (HKLM, HKCU, HKU, HKCR, HKCC) |
| path | No | SOFTWARE | Starting registry path within the hive |
| max_depth | No | 5 | Maximum recursion depth for subkey traversal |
| max_results | No | 50 | Maximum number of results to return |

## Usage

```
# Search for "Microsoft" in HKLM\SOFTWARE (default)
reg-search -pattern Microsoft

# Search a specific path with limited depth
reg-search -pattern Windows -hive HKLM -path SOFTWARE\Microsoft -max_depth 2

# Search HKCU for user-specific settings
reg-search -pattern Environment -hive HKCU -path Environment -max_depth 1

# Search for persistence-related keys
reg-search -pattern Run -hive HKLM -path SOFTWARE\Microsoft\Windows\CurrentVersion -max_depth 2

# Search with more results
reg-search -pattern password -hive HKLM -path SOFTWARE -max_results 100
```

### Value Types

The command reads and searches across all common registry value types:

| Type | Display Format |
|------|---------------|
| REG_SZ / REG_EXPAND_SZ | String value |
| REG_DWORD / REG_QWORD | Decimal (hex) — e.g., `1234 (0x4d2)` |
| REG_BINARY | Hex bytes (first 64 bytes) |
| REG_MULTI_SZ | Semicolon-separated strings |

### OPSEC Notes

- Uses standard `RegOpenKeyEx`, `RegEnumKeyEx`, and `RegEnumValue` API calls
- Read-only — does not modify any registry keys or values
- Respects max_depth and max_results limits to control execution time
- Access may be denied on certain protected keys (silently skipped)

## MITRE ATT&CK Mapping

- **T1012** - Query Registry
