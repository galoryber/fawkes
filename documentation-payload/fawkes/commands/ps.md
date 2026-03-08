+++
title = "ps"
chapter = false
weight = 103
hidden = false
+++

## Summary

List running processes with Mythic process browser integration. Returns structured process data including PID, PPID, name, user, architecture, binary path, and command line. Cross-platform (Windows, Linux, macOS).

Integrates with Mythic's **Process Browser** UI — clicking the process browser icon in the callback table runs `ps` and displays results in a sortable, interactive table with expandable details for each process.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| filter | No | — | Filter by process name (case-insensitive substring match) |
| pid | No | 0 | Filter by specific process ID |
| ppid | No | 0 | Filter by parent process ID (find child processes) |
| user | No | — | Filter by username (case-insensitive substring match) |
| verbose | No | false | Include command line in output (CLI: `-v`) |

## Usage
```
# List all processes
ps

# Filter by name
ps -filter svchost

# Filter by specific PID
ps -pid 1234

# Find all children of a parent process
ps -ppid 612

# Filter by user
ps -user SYSTEM

# Combine filters
ps -filter svc -user SYSTEM

# Legacy CLI syntax still works
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
