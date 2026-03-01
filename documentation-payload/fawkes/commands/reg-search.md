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

### Output Format

Returns a JSON array of match objects rendered as a sortable table via browser script:

```json
[
  {"key_path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "value_name": "SecurityHealth", "value_data": "C:\\Windows\\..."},
  {"key_path": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "value_name": "", "value_data": ""}
]
```

| Field | Description |
|-------|-------------|
| key_path | Full registry key path |
| value_name | Matching value name (empty for key-only matches) |
| value_data | Value data content (empty for key-only matches) |

Value matches are highlighted in the browser script table. Supports REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_BINARY (first 64 bytes hex), and REG_MULTI_SZ (semicolon-separated).

### OPSEC Notes

- Uses standard `RegOpenKeyEx`, `RegEnumKeyEx`, and `RegEnumValue` API calls
- Read-only — does not modify any registry keys or values
- Respects max_depth and max_results limits to control execution time
- Access may be denied on certain protected keys (silently skipped)

## MITRE ATT&CK Mapping

- **T1012** - Query Registry
