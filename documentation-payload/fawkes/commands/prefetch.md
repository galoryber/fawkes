+++
title = "prefetch"
chapter = false
weight = 156
hidden = false
+++

## Summary

Parse and manage Windows Prefetch files for forensic analysis or anti-forensics. Prefetch files record application execution history — which programs ran, how many times, and when. This command can enumerate executed programs, parse detailed execution history, and delete prefetch files to remove forensic evidence.

Supports MAM-compressed prefetch files used by Windows 10/11 and all prefetch versions (17/23/26/30).

{{% notice info %}}Windows Only{{% /notice %}}

{{% notice warning %}}Delete/clear actions require administrative privileges{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | list | Action: `list`, `parse`, `delete`, or `clear` |
| name | No | | Executable name to filter (e.g., `CMD.EXE`, `POWERSHELL`) |
| count | No | 50 | Maximum entries for list action |

### Actions

- **list** — Show prefetch files sorted by most recent execution, with run count and last run time
- **parse** — Detailed parsing of specific prefetch files (run count, run history with up to 8 timestamps)
- **delete** — Delete prefetch files matching a specific executable name
- **clear** — Delete ALL prefetch files from the Prefetch directory

## Usage

```
# List recently executed programs
prefetch -action list

# List prefetch entries for a specific program
prefetch -action list -name powershell

# Parse detailed execution history
prefetch -action parse -name CMD.EXE

# Delete prefetch evidence for specific program
prefetch -action delete -name PAYLOAD

# Clear all prefetch files
prefetch -action clear
```

## Operational Notes

- Prefetch directory: `%WINDIR%\Prefetch`
- Windows 10/11 compress prefetch files using MAM format — this command handles decompression automatically
- Prefetch version 26/30 stores up to 8 historical run timestamps
- Clearing prefetch removes evidence of what programs have executed on the system
- New prefetch files will be created when programs run again (unless Prefetch is disabled via registry)
- Consider disabling Prefetch after clearing: `reg-write -hive HKLM -key "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -value EnablePrefetcher -type dword -data 0`

## MITRE ATT&CK Mapping

- **T1070.004** — Indicator Removal: File Deletion
