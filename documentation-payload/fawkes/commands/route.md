+++
title = "route"
chapter = false
weight = 122
hidden = false
+++

## Summary

Display the system routing table. Essential for understanding network segmentation, identifying pivot opportunities, and mapping internal network topology during post-exploitation.

Cross-platform — works on Windows, Linux, and macOS.

## Arguments

No arguments required.

## Usage

### Display routing table
```
route
```

## Output

Shows routing table entries with:
- **Destination** — Target network/host
- **Gateway** — Next-hop gateway address
- **Netmask** — Network mask
- **Interface** — Network interface name
- **Metric** — Route metric/priority
- **Flags** — Route flags (UG=gateway, UH=host, etc.)

## Platform Details

### Windows
Uses `GetIpForwardTable` API from `iphlpapi.dll` for IPv4 routing table. Resolves interface index to friendly names (e.g., "Ethernet 2", "Loopback Pseudo-Interface 1"). Route types: direct (local subnet), indirect (via gateway).

### Linux
Parses `/proc/net/route` for IPv4 routes and `/proc/net/ipv6_route` for IPv6 routes. Decodes hex-encoded addresses. Flags: U=up, G=gateway, H=host, D=dynamic, M=modified.

### macOS
Parses output of `netstat -rn` for routing table entries. Supports both IPv4 and IPv6 routes.

## OPSEC Considerations

- Read-only enumeration — no modifications to the routing table
- Uses standard APIs and /proc filesystem — minimal footprint
- `netstat` subprocess on macOS may appear in process list briefly

## MITRE ATT&CK Mapping

- **T1016** — System Network Configuration Discovery
