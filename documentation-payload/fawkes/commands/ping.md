+++
title = "ping"
chapter = false
weight = 207
hidden = false
+++

## Summary

TCP connect-based host reachability check with subnet sweep support. Probes a specified port on one or more hosts to determine if they are alive and listening. Supports CIDR notation, dash ranges, comma-separated lists, and hostname resolution.

Unlike ICMP ping which requires raw sockets, this uses TCP connect probes which work at normal user privilege levels and are less likely to be blocked by firewalls.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| hosts | Yes | | Target host(s) — single IP, comma-separated, CIDR (192.168.1.0/24), or dash range (192.168.1.1-254) |
| port | No | 445 | TCP port to probe |
| timeout | No | 1000 | Timeout per host in milliseconds |
| threads | No | 25 | Concurrent connections (max: 100) |

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

## OPSEC Considerations

- TCP connect creates a full connection (SYN → SYN-ACK → ACK → RST). This generates network events and may be logged by firewalls/IDS.
- Large sweeps (e.g., /16) are noisy. Use smaller ranges and lower thread counts for stealth.
- Port 445 (default) is commonly monitored. Consider using port 80 or 443 for less suspicious probing.

## MITRE ATT&CK Mapping

- **T1018** — Remote System Discovery
