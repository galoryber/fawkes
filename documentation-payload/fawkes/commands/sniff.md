+++
title = "sniff"
chapter = false
weight = 175
hidden = false
+++

## Summary

Passive network sniffing for credential capture. Opens a raw socket to capture network traffic and automatically extracts cleartext credentials from HTTP Basic Auth, FTP USER/PASS, NTLM authentication messages, and Kerberos AS-REP/TGS-REP principals.

Cross-platform: Windows (SIO_RCVALL raw sockets), Linux (AF_PACKET + BPF kernel filtering), macOS (/dev/bpf).

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| interface | No | auto-detect | Network interface name or IP address. Windows accepts interface name (e.g. "Ethernet") or IP. Linux/macOS: e.g. eth0, en0 |
| duration | No | 30 | Capture duration in seconds (max: 300) |
| ports | No | 21,80,110,143,389,445,8080 | Comma-separated TCP ports to filter |
| promiscuous | No | false | Enable promiscuous mode to capture traffic not destined for this host |
| max_bytes | No | 52428800 (50MB) | Stop after capturing this many bytes |
| save_pcap | No | false | Save raw packet capture as PCAP file (downloadable via Mythic) |

## Usage

### Basic capture (30 seconds, default ports)
```
sniff
```

### Capture on specific interface with promiscuous mode
```
sniff -interface eth0 -promiscuous true -duration 60
```

### Windows: capture on specific adapter
```
sniff -interface Ethernet -duration 60
sniff -interface 192.168.1.50 -duration 60
```

### Target specific ports (include Kerberos)
```
sniff -ports 21,80,88,445 -duration 120
```

### Capture with PCAP file download
```
sniff -duration 30 -save_pcap true
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
- **Kerberos AS-REP**: Extracts client principal name and realm from AS-REP messages (port 88). Useful for identifying AS-REP roastable accounts (T1558.004)
- **Kerberos TGS-REP**: Extracts service principal name and realm from TGS-REP messages

## Platform Details

| Platform | Mechanism | Notes |
|----------|-----------|-------|
| Windows | `SIO_RCVALL` raw socket | Requires Administrator. Binds to specific IP. No ethernet headers. |
| Linux | `AF_PACKET` raw socket | Requires root or `CAP_NET_RAW`. BPF kernel-level port filtering. |
| macOS | `/dev/bpf` device | Requires root. Userspace port filtering. |

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
    },
    {
      "protocol": "krb-asrep",
      "src_ip": "192.168.1.10",
      "src_port": 88,
      "dst_ip": "192.168.1.50",
      "dst_port": 49900,
      "username": "jdoe@CONTOSO.COM",
      "detail": "realm=CONTOSO.COM",
      "timestamp": 1711900020
    }
  ]
}
```

## OPSEC Considerations

- **Windows**: Requires Administrator. `SIO_RCVALL` may be flagged by EDR/security products
- **Linux/macOS**: Requires root or `CAP_NET_RAW` capability
- **Promiscuous mode** changes NIC state and can be detected by tools like `promiscdetect` or `antisniff`
- Raw socket creation may trigger host-based IDS alerts
- Captured traffic stays in memory only — no PCAP file written to disk
- BPF filter (Linux) reduces kernel-to-userspace traffic volume

## MITRE ATT&CK Mapping

- **T1040** — Network Sniffing
- **T1558.004** — Steal or Forge Kerberos Tickets: AS-REP Roasting
