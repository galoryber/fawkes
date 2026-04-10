+++
title = "arp"
chapter = false
weight = 103
hidden = false
+++

## Summary

Display the ARP table or perform ARP cache poisoning for man-in-the-middle positioning. Two modes:

- **Default (list):** Display IP-to-MAC address mappings for hosts on the local network.
- **spoof:** Bidirectional ARP cache poisoning (T1557.002) — send gratuitous ARP replies to position as MITM between a target and gateway. Enables IP forwarding, runs for configurable duration, and restores original ARP entries on cleanup.

### Implementation

- **Windows**: Uses `GetIpNetTable` Win32 API from `iphlpapi.dll` (no subprocess)
- **Linux**: Reads `/proc/net/arp` directly (no subprocess)
- **macOS**: Uses `arp -a` (subprocess, no native API alternative)

## Arguments

### ARP Table (Default)

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| ip | No | — | Filter by IP address (substring match, e.g. '192.168') |
| mac | No | — | Filter by MAC address (substring match, case-insensitive) |
| interface | No | — | Filter by interface name (case-insensitive exact match) |

### ARP Spoof

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | — | Must be `spoof` |
| target | Yes | — | Victim IP to poison |
| gateway | Yes | — | Gateway IP to impersonate |
| interface | No | auto-detect | Network interface for raw socket |
| duration | No | 120 | Spoofing duration in seconds (max: 600) |
| interval | No | 2 | Seconds between ARP reply packets |

## Usage

```
# Show all ARP entries
arp

# Filter by IP subnet
arp -ip 192.168

# Filter by MAC prefix
arp -mac 52:54:00

# Filter by interface
arp -interface eth0

# Combine filters
arp -ip 192.168 -interface eth0
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

## ARP Spoof Usage

```
# Classic MITM: position between victim and gateway
arp -action spoof -target 192.168.1.50 -gateway 192.168.1.1

# Custom duration and interval
arp -action spoof -target 10.0.0.100 -gateway 10.0.0.1 -duration 300 -interval 5

# Specify interface
arp -action spoof -target 172.16.0.50 -gateway 172.16.0.1 -interface eth0
```

### How It Works

1. Resolves MAC addresses for target and gateway from ARP cache
2. Enables kernel IP forwarding (`/proc/sys/net/ipv4/ip_forward`)
3. Sends bidirectional gratuitous ARP replies:
   - Tells target: "Gateway IP has attacker's MAC"
   - Tells gateway: "Target IP has attacker's MAC"
4. Traffic between target and gateway routes through attacker
5. On stop: restores original ARP entries and IP forwarding state

{{% notice info %}}Linux Only — requires root for AF_PACKET raw sockets{{% /notice %}}

### OPSEC Considerations

{{% notice warning %}}CRITICAL: ARP spoofing is highly detectable{{% /notice %}}

- Gratuitous ARP replies are flagged by Dynamic ARP Inspection (DAI) on managed switches
- ARP storm detection may trigger port security violations
- Duplicate IP warnings appear on poisoned hosts
- Network monitoring tools (arpwatch, XArp) specifically detect ARP cache changes
- IP forwarding modification is logged by host-based monitoring

## MITRE ATT&CK Mapping

- T1016.001 -- System Network Configuration Discovery: Internet Connection Discovery
- T1557.002 -- Adversary-in-the-Middle: ARP Cache Poisoning
