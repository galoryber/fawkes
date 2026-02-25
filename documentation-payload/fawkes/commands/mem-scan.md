+++
title = "mem-scan"
chapter = false
weight = 104
hidden = false
+++

## Summary

Search a target process's virtual memory for byte patterns (string or hex). Returns matches with addresses, region info, and hex dump context with ASCII sidebar.

Windows uses VirtualQueryEx + ReadProcessMemory. Linux reads /proc/pid/maps + /proc/pid/mem.

Windows and Linux only.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| pid | Yes | — | Target process ID to scan |
| pattern | Yes | — | Search pattern (string or hex bytes) |
| hex | No | false | Treat pattern as hex-encoded bytes (e.g. `4d5a9000`) |
| max_results | No | 50 | Maximum number of matches to return |
| context_bytes | No | 32 | Bytes of context around each match in hex dump |

## Usage

```
# Search own process memory for a string
mem-scan -pid 1234 -pattern "password"

# Search for MZ header (PE) using hex pattern
mem-scan -pid 1234 -pattern "4d5a9000" -hex

# Search for ELF magic on Linux
mem-scan -pid 5678 -pattern "7f454c46" -hex

# Limit results and context
mem-scan -pid 1234 -pattern "secret" -max_results 10 -context_bytes 64
```

## Example Output

```
Memory Scan: PID 6320
Pattern: fawkes (6 bytes)
Regions scanned: 3 | Bytes scanned: 1.4 MB
Matches found: 5 (limit reached, use -max_results to increase)
--------------------------------------------------------------------------------

Match 1: 0xC00000B970 (region base 0xC000000000 + 0xB970)
  0xC00000B960   01  00  00  00  00  00  00  00  02  00  00  00  00  00  00  00  |................|
  0xC00000B970  [66][61][77][6b][65][73] 00  00  68  74  74  70  00  00  00  00  |fawkes..http....|
  0xC00000B980   70  61  79  6c  6f  61                                          |payloa|
```

## OPSEC Considerations

- Opens target process with PROCESS_VM_READ + PROCESS_QUERY_INFORMATION — may trigger EDR alerts
- ReadProcessMemory calls are monitored by many security products
- On Linux, reading /proc/pid/mem requires appropriate permissions (ptrace_scope)
- Scanning large processes generates significant memory I/O
- Regions >256 MB are automatically skipped to avoid hanging

## MITRE ATT&CK Mapping

- **T1005** — Data from Local System
- **T1057** — Process Discovery
