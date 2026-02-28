+++
title = "amcache"
chapter = false
weight = 156
hidden = false
+++

## Summary

Query and clean Windows Shimcache (AppCompatCache) execution history. Shimcache records program execution metadata in the registry, which is a key forensic artifact used by incident responders to determine what programs have been run on a system.

Cleaning the Shimcache removes evidence of tool execution, complementing other anti-forensics commands (prefetch, usn-jrnl, eventlog, history-scrub).

Uses the `golang.org/x/sys/windows/registry` package for direct registry access — no external process creation.

{{% notice info %}}Windows Only{{% /notice %}}

{{% notice warning %}}Delete/clear actions require administrative privileges (registry write to HKLM){{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | query | Action: `query`, `search`, `delete`, or `clear` |
| name | No | | Executable name or path pattern (case-insensitive substring match) |
| count | No | 50 | Maximum entries to display (for query action) |

### Actions

- **query** — List Shimcache entries showing program paths and last modification timestamps
- **search** — Search for specific executable name or path pattern in the Shimcache
- **delete** — Remove entries matching the specified name pattern from the Shimcache
- **clear** — Remove all Shimcache entries

## Usage

```
# View recent Shimcache entries
amcache -action query

# View more entries
amcache -action query -count 200

# Search for specific executable
amcache -action search -name fawkes

# Search for all PowerShell-related entries
amcache -action search -name powershell

# Delete entries matching a pattern
amcache -action delete -name fawkes.exe

# Clear all Shimcache entries
amcache -action clear
```

## Output Format

The `query` and `search` actions return a JSON array rendered as a sortable table via browser script:
```json
[
  {
    "index": 0,
    "last_modified": "2025-01-15 14:30:22",
    "path": "\\??\\C:\\Windows\\System32\\cmd.exe"
  }
]
```

The browser script highlights suspicious executables (powershell, cmd, wscript, cscript, mshta) in orange. Other actions (delete, clear) return plain text status messages.

## Operational Notes

- **Shimcache vs Amcache**: This command targets the Shimcache (AppCompatCache registry value), which is the in-memory execution tracker. The Amcache.hve hive file is a separate artifact.
- **Shimcache persistence**: The Shimcache is written to the registry on system shutdown. Changes take effect immediately in the registry but the in-memory cache may still contain entries until the next reboot.
- **Format support**: Automatically detects Windows 10/11 format (signature `10ts`/`0x30747331`) and Windows 8/8.1 format.
- **Delete operations** rewrite the entire AppCompatCache registry value with matching entries removed.
- **Combine with other anti-forensics**: Use alongside `prefetch -action clear`, `usn-jrnl -action delete`, `auditpol -action stealth`, and `eventlog -action clear` for comprehensive evidence removal.

## MITRE ATT&CK Mapping

- **T1070.004** — Indicator Removal: File Deletion
