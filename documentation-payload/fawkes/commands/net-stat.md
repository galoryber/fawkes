+++
title = "net-stat"
chapter = false
weight = 110
hidden = false
+++

## Summary

List active network connections and listening ports. Shows protocol, local address, remote address, connection state, PID, and process name. Supports filtering by state, protocol, port, and process ID.

Cross-platform — works on Windows, Linux, and macOS.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| state | No | — | Filter by connection state: LISTEN, ESTABLISHED, TIME_WAIT, CLOSE_WAIT, SYN_SENT, etc. |
| proto | No | — | Filter by protocol: tcp or udp |
| port | No | — | Filter by port number (matches local or remote port) |
| pid | No | — | Filter by process ID |

## Usage
```
# Show all connections (default)
net-stat

# Show only listening ports
net-stat -state LISTEN

# Show only TCP connections
net-stat -proto tcp

# Show connections on port 443
net-stat -port 443

# Show connections for a specific process
net-stat -pid 3456

# Combine filters: TCP connections in ESTABLISHED state
net-stat -state ESTABLISHED -proto tcp
```

### Example Output
```
47 connections

Proto  Local Address             Remote Address            State           PID    Process
---------------------------------------------------------------------------------------------
TCP    0.0.0.0:135               *:*                       LISTEN          1044   svchost.exe
TCP    0.0.0.0:445               *:*                       LISTEN          4      System
TCP    0.0.0.0:5985              *:*                       LISTEN          4      System
TCP    192.168.100.192:49721     192.168.100.184:443       ESTABLISHED     3456   fawkes.exe
TCP    192.168.100.192:49722     13.107.42.16:443          ESTABLISHED     2100   msedge.exe
UDP    0.0.0.0:5353              *:*                       -               1876   svchost.exe
```

Connections are sorted by state (LISTEN first, then ESTABLISHED) and then by local port.

## Operational Notes

- Without filters, all connections (TCP and UDP) are returned
- Filters are case-insensitive for state and protocol
- Port filter matches either local or remote port
- Combine multiple filters to narrow results (e.g., `-state ESTABLISHED -proto tcp -port 443`)
- Process names are resolved from PIDs for quick identification of which application owns each connection
- Useful for identifying C2 connections (`-state ESTABLISHED`), open services (`-state LISTEN`), or processes with network activity (`-pid`)

## MITRE ATT&CK Mapping

- T1049 — System Network Connections Discovery
