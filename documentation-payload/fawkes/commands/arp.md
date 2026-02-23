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

### Example Output
```
IP Address         MAC Address          Type       Interface
--------------------------------------------------------------
192.168.100.1      9e:05:d6:df:79:22    dynamic    eth0
192.168.100.99     e0:d4:64:8e:f0:a3    dynamic    eth0
192.168.100.184    52:54:00:12:34:56    static     eth0

[3 ARP entries found]
```

## MITRE ATT&CK Mapping

- T1016.001 -- System Network Configuration Discovery: Internet Connection Discovery
