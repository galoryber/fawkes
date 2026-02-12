+++
title = "arp"
chapter = false
weight = 103
hidden = false
+++

## Summary

Display the ARP (Address Resolution Protocol) table, showing IP-to-MAC address mappings for hosts that have been recently communicated with on the local network. Useful for host discovery and network reconnaissance.

Cross-platform: uses `arp -a` on Windows/macOS and `ip neigh show` on Linux (falls back to `arp -a`).

## Arguments

None.

## Usage

```
arp
```

### Example Output (Windows)
```
Interface: 192.168.100.192 --- 0xb
  Internet Address      Physical Address      Type
  192.168.100.1         9e-05-d6-df-79-22     dynamic
  192.168.100.99        e0-d4-64-8e-f0-a3     dynamic
  192.168.100.184       52-54-00-12-34-56     dynamic

[3 ARP entries found]
```

### Example Output (Linux)
```
192.168.100.1 dev eth0 lladdr 9e:05:d6:df:79:22 REACHABLE
192.168.100.184 dev eth0 lladdr 52:54:00:12:34:56 STALE

[2 ARP entries found]
```

## MITRE ATT&CK Mapping

- T1016.001 -- System Network Configuration Discovery: Internet Connection Discovery
