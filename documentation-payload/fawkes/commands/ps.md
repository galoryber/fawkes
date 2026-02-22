+++
title = "ps"
chapter = false
weight = 103
hidden = false
+++

## Summary

List running processes with Mythic process browser integration. Returns structured process data including PID, PPID, name, user, architecture, binary path, and command line. Cross-platform (Windows, Linux, macOS).

Integrates with Mythic's **Process Browser** UI — clicking the process browser icon in the callback table runs `ps` and displays results in a sortable, interactive table with expandable details for each process.

### Arguments

#### -v (optional)
Verbose mode (same JSON output, retained for CLI compatibility).

#### -i PID (optional)
Filter by a specific process ID.

#### filter (optional)
Search by process name (case-insensitive).

## Usage
```
ps [-v] [-i PID] [filter]
```

Example
```
ps
ps svchost
ps -i 1234
ps -v explorer
```

### Output Format

Returns a JSON array of process entries:
```json
[
  {
    "process_id": 612,
    "parent_process_id": 4,
    "architecture": "x64",
    "name": "svchost.exe",
    "user": "NT AUTHORITY\\SYSTEM",
    "bin_path": "C:\\Windows\\System32\\svchost.exe",
    "command_line": "C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted -p"
  }
]
```

The browser script renders this as a sortable table with:
- PID (with copy button)
- PPID
- Architecture
- Process name
- User
- Expandable details button (binary path, command line, etc.)

## MITRE ATT&CK Mapping

- T1057 — Process Discovery
