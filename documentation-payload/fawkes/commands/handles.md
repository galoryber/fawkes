+++
title = "handles"
chapter = false
weight = 120
hidden = false
+++

{{% notice info %}}Windows Only{{% /notice %}}

## Summary

Enumerate open handles in a target process using `NtQuerySystemInformation(SystemHandleInformation)`. Shows handle types, counts, and optionally resolves handle names via `NtQueryObject`.

Useful for injection reconnaissance (finding target DLLs, named pipes, mutexes), detecting security tools (by their handle signatures), and understanding process relationships.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| pid | Yes | — | Target process ID to enumerate handles for |
| type | No | all types | Filter by handle type (e.g. File, Key, Section, Mutant, Event, Process, Thread) |
| show_names | No | false | Resolve handle names (slower but more detailed) |
| max_count | No | 500 | Maximum number of handles to enumerate |

## Usage

```
# Handle type summary for a process
handles -pid 1234

# Show File handles with resolved names
handles -pid 1234 -type File -show_names

# All handles with names (slower)
handles -pid 1234 -show_names -max_count 1000

# Filter for registry key handles
handles -pid 1234 -type Key -show_names
```

### Browser Script

Output is rendered as sortable tables in the Mythic UI:
1. **Type summary table**: Handle type and count, sorted by count descending
2. **Handle detail table**: Handle value, type, and name. Color-coded: File (blue), Key (orange), Process/Thread (red)

## Example Output (JSON)
```json
{
  "pid": 5408, "shown": 172, "total": 172, "system": 71997,
  "summary": [
    {"type": "Event", "count": 29},
    {"type": "File", "count": 26}
  ],
  "handles": [
    {"handle": 4, "type": "File", "name": "\\Device\\ConDrv"},
    {"handle": 16, "type": "File", "name": "\\Device\\Null"}
  ]
}
```

## Common Handle Types

| Type | Description |
|------|-------------|
| File | Open files, directories, devices, named pipes |
| Key | Registry key handles |
| Event | Synchronization events |
| Section | Memory-mapped file sections |
| Mutant | Named mutexes |
| Thread | Thread handles |
| Process | Process handles |
| Token | Access tokens |
| Semaphore | Counting semaphores |
| ALPC Port | Advanced Local Procedure Call ports |
| Directory | Object manager directories |

## Implementation

- Uses `NtQuerySystemInformation(SystemHandleInformation)` to enumerate all system handles
- Filters to target PID, then duplicates each handle via `NtDuplicateObject`
- Resolves type/name via `NtQueryObject` on the duplicated handle
- Skips deadlock-prone types (ALPC Port, WaitCompletionPacket, etc.) for name resolution
- Handles where `NtDuplicateObject` fails are shown as `Type_N` (access-restricted)

## OPSEC Considerations

- Calls `NtQuerySystemInformation` which enumerates ALL system handles — may trigger EDR monitoring
- Requires `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE` access to target process
- Name resolution involves `NtQueryObject` which creates brief handle activity
- Higher privilege allows accessing more process handles

## MITRE ATT&CK Mapping

- **T1057** — Process Discovery
- **T1082** — System Information Discovery
