+++
title = "port-scan"
chapter = false
weight = 115
hidden = false
+++

## Summary

TCP connect scan for network service discovery. Scans specified hosts and ports concurrently to identify open TCP services.

Cross-platform — works on Windows, Linux, and macOS.

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| hosts | string | Yes | - | Comma-separated IPs, CIDR ranges, or IP ranges (e.g., `192.168.1.1`, `10.0.0.0/24`, `192.168.1.1-10`) |
| ports | string | No | Common ports | Comma-separated ports or ranges (e.g., `80,443,8080` or `1-1024`) |
| timeout | number | No | 2 | Connection timeout per port in seconds |
| concurrency | number | No | 100 | Maximum concurrent TCP connections |

Default ports when not specified: 21,22,23,25,53,80,88,110,135,139,143,389,443,445,993,995,1433,1521,3306,3389,5432,5900,5985,8080,8443

## Usage

Scan a single host with default ports:
```
port-scan -hosts 192.168.1.1
```

Scan a subnet on specific ports:
```
port-scan -hosts 192.168.1.0/24 -ports 22,80,443,3389
```

Scan an IP range:
```
port-scan -hosts 10.0.0.1-20 -ports 1-1024 -timeout 1 -concurrency 200
```

### Example Output
```
Scanned 25 ports across 1 hosts (25 total probes)
Found 4 open ports

Host                 Port     Service
--------------------------------------------------
192.168.100.184      22       SSH
192.168.100.184      80       HTTP
192.168.100.184      443      HTTPS
192.168.100.184      7443
```

### Host Format

- Single IP: `192.168.1.1`
- CIDR notation: `192.168.1.0/24` (max 1024 hosts)
- IP range shorthand: `192.168.1.1-10`
- Hostname: `server.internal`
- Comma-separated mix: `192.168.1.1,10.0.0.0/24,webserver`

### Safety Limits

- Maximum 1024 hosts per CIDR or range
- Maximum 10,000 ports per range
- Configurable timeout and concurrency to control scan speed/noise

## MITRE ATT&CK Mapping

- T1046 — Network Service Discovery
