+++
title = "arp"
chapter = false
weight = 103
hidden = false
+++

## Summary

Display the ARP (Address Resolution Protocol) table, showing IP-to-MAC address mappings for hosts that have been recently communicated with on the local network. Useful for host discovery and network reconnaissance.

### Implementation

- **Windows**: Uses `GetIpNetTable` Win32 API from `iphlpapi.dll` (no subprocess)
- **Linux**: Reads `/proc/net/arp` directly (no subprocess)
- **macOS**: Uses `arp -a` (subprocess, no native API alternative)

## Arguments

None.

## Usage

```
arp
```

### Browser Script

Output is rendered as a sortable table in the Mythic UI with columns: IP, MAC, Type, Interface. Static entries are highlighted.

### Example Output (JSON)
```json
[
  {"ip":"192.168.100.1","mac":"9e:05:d6:df:79:22","type":"dynamic","interface":"eth0"},
  {"ip":"192.168.100.184","mac":"52:54:00:12:34:56","type":"static","interface":"eth0"}
]
```

## MITRE ATT&CK Mapping

- T1016.001 -- System Network Configuration Discovery: Internet Connection Discovery
