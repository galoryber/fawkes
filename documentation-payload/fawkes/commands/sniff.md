+++
title = "sniff"
chapter = false
weight = 175
hidden = false
+++

## Summary

Passive network sniffing for credential capture. Opens a raw socket (AF_PACKET) to capture network traffic and automatically extracts cleartext credentials from HTTP Basic Auth, FTP USER/PASS, and NTLM authentication messages.

{{% notice info %}}Linux and macOS{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| interface | No | all | Network interface (e.g. eth0, ens33). Empty captures on all interfaces |
| duration | No | 30 | Capture duration in seconds (max: 300) |
| ports | No | 21,80,110,143,389,445,8080 | Comma-separated TCP ports to filter via BPF |
| promiscuous | No | false | Enable promiscuous mode to capture traffic not destined for this host |
| max_bytes | No | 52428800 (50MB) | Stop after capturing this many bytes |

## Usage

### Basic capture (30 seconds, default ports)
```
sniff
```

### Capture on specific interface with promiscuous mode
```
sniff -interface eth0 -promiscuous true -duration 60
```

### Target specific ports
```
sniff -ports 21,80,445 -duration 120
```

### Quick 10-second scan
```
sniff -duration 10
```

## Credential Extraction

The sniffer automatically detects and extracts:

- **HTTP Basic Auth**: Decodes `Authorization: Basic <base64>` headers from HTTP requests
- **FTP Credentials**: Correlates `USER` and `PASS` commands across TCP packets
- **NTLM Authentication**: Extracts domain\username from NTLM Type 3 (Authenticate) messages in HTTP, SMB, LDAP

## Output Format

JSON output with capture statistics and discovered credentials:

```json
{
  "duration": "30s",
  "packet_count": 1542,
  "bytes_captured": 892441,
  "credentials": [
    {
      "protocol": "http-basic",
      "src_ip": "192.168.1.50",
      "src_port": 49832,
      "dst_ip": "192.168.1.100",
      "dst_port": 80,
      "username": "admin",
      "password": "P@ssw0rd",
      "timestamp": 1711900000
    },
    {
      "protocol": "ntlm",
      "src_ip": "192.168.1.50",
      "dst_ip": "192.168.1.10",
      "dst_port": 445,
      "username": "DOMAIN\\jsmith",
      "detail": "host=WORKSTATION01",
      "timestamp": 1711900015
    }
  ]
}
```

## OPSEC Considerations

- Requires **root** or **CAP_NET_RAW** capability
- **Promiscuous mode** changes NIC state and can be detected by tools like `promiscdetect` or `antisniff`
- Raw socket creation may trigger host-based IDS alerts
- Captured traffic stays in memory only — no PCAP file written to disk
- BPF filter reduces kernel-to-userspace traffic volume (OPSEC benefit: less CPU usage)

## MITRE ATT&CK Mapping

- **T1040** — Network Sniffing
