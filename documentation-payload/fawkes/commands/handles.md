+++
title = "handles"
chapter = false
weight = 120
hidden = false
+++

{{% notice info %}}Windows, Linux, and macOS{{% /notice %}}

## Summary

Enumerate open handles or file descriptors in a target process. Cross-platform command with platform-specific enumeration methods.

### Windows
Uses `NtQuerySystemInformation(SystemHandleInformation)` to enumerate NT handles. Shows handle types (File, Key, Section, Mutant, etc.), counts, and optionally resolves handle names via `NtQueryObject`.

### Linux
Reads `/proc/<pid>/fd` symlinks to enumerate open file descriptors. Classifies targets as file, socket, pipe, device, tty, eventfd, etc.

### macOS
Uses `lsof -p <pid>` to enumerate open file descriptors. Classifies types as file, socket, pipe, device, directory, kqueue, etc.

Useful for:
- **Injection recon**: Finding target DLLs, named pipes, mutexes (Windows)
- **IPC discovery**: Identify open sockets, pipes, and communication channels
- **Security tool detection**: Recognizing security products by their handle/fd signatures
- **Process analysis**: Understanding what files and resources a process has open

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| pid | Yes | — | Target process ID to enumerate handles for |
| type | No | all types | Filter by handle/fd type (platform-specific, case-insensitive) |
| show_names | No | false | Resolve handle names (Windows only — Linux/macOS always show names) |
| max_count | No | 500 | Maximum number of handles to enumerate |

## Usage

```
# Handle/fd summary for a process
handles -pid 1234

# Filter by type
handles -pid 1234 -type file
handles -pid 1234 -type socket

# Windows: show handle names
handles -pid 1234 -type File -show_names

# Enumerate more handles
handles -pid 1234 -max_count 1000
```

### Browser Script

Output is rendered as sortable tables in the Mythic UI:
1. **Type summary table**: Handle type and count, sorted by count descending
2. **Handle detail table**: Handle value/fd number, type, and name. Color-coded: File (blue), Key (orange), Process/Thread (red)

## Example Output

### Windows
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

### Linux
```json
{
  "pid": 1234, "shown": 15, "total": 15,
  "summary": [
    {"type": "file", "count": 8},
    {"type": "socket", "count": 4},
    {"type": "pipe", "count": 2},
    {"type": "device", "count": 1}
  ],
  "handles": [
    {"handle": 0, "type": "device", "name": "/dev/null"},
    {"handle": 3, "type": "file", "name": "/tmp/data.log"},
    {"handle": 5, "type": "socket", "name": "socket:[12345]"},
    {"handle": 7, "type": "pipe", "name": "pipe:[67890]"}
  ]
}
```

### macOS
```json
{
  "pid": 5678, "shown": 12, "total": 14,
  "summary": [
    {"type": "file", "count": 5},
    {"type": "socket", "count": 3},
    {"type": "pipe", "count": 2}
  ],
  "handles": [
    {"handle": 0, "type": "device", "name": "/dev/null"},
    {"handle": 3, "type": "file", "name": "/Users/user/data.txt"},
    {"handle": 5, "type": "socket", "name": "/var/run/mDNSResponder"}
  ]
}
```

## Handle/FD Types by Platform

### Windows
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

### Linux
| Type | Description |
|------|-------------|
| file | Regular files |
| socket | Network sockets (TCP, UDP, Unix) |
| pipe | Anonymous pipes |
| device | Device files (/dev/*) |
| tty | Terminal devices |
| eventfd | Event file descriptors |
| eventpoll | epoll instances |
| timerfd | Timer file descriptors |

### macOS
| Type | Description |
|------|-------------|
| file | Regular files |
| directory | Open directories |
| socket | Network and Unix sockets |
| pipe | Pipes and FIFOs |
| device | Character devices |
| kqueue | Kernel event queues |

## OPSEC Considerations

- **Windows**: Calls `NtQuerySystemInformation` (enumerates ALL system handles) — may trigger EDR monitoring. Requires `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE` access.
- **Linux**: Reads `/proc/<pid>/fd` — no process spawning, minimal footprint. Requires read access to target's proc directory (same user or root/CAP_SYS_PTRACE).
- **macOS**: Spawns `lsof` process — creates a process creation artifact. Requires permissions to view target process.

## MITRE ATT&CK Mapping

- **T1057** — Process Discovery
- **T1082** — System Information Discovery
