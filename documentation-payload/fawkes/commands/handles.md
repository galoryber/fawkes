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

## Example Output

### Type Summary
```
Handles for PID 5408: 172 shown (172 total, 71997 system-wide)

Handle Type Summary:
  Event                          29
  File                           26
  IRTimer                        20
  WaitCompletionPacket           15
  Thread                         12
  Key                            9
  ALPC Port                      6
  IoCompletion                   4
  TpWorkerFactory                3
  Mutant                         2
  Semaphore                      2
  Directory                      2
```

### File Handles with Names
```
Handles for PID 5408: 5 shown (172 total, 72004 system-wide)

Handle Type Summary:
  File                           5

Handle   Type                      Name
--------------------------------------------------------------------------------
0x4      File                      \Device\ConDrv
0x10     File                      \Device\Null
0x5C     File                      \Device\HarddiskVolume3\Users\setup
0x64     File                      \Device\ConDrv
0xC8     File                      \Device\CNG
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
