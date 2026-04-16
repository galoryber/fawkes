+++
title = "socks"
chapter = false
weight = 103
hidden = false
+++

## Summary

Start or stop a SOCKS5 proxy through the agent's callback. Supports both TCP CONNECT and UDP ASSOCIATE (RFC 1928) relay for routing TCP and UDP traffic through the agent. Optional per-connection bandwidth limiting prevents noisy traffic patterns.

Mythic handles SOCKS5 authentication on the server side. The agent parses SOCKS5 requests, establishes connections to targets, and relays data bidirectionally through the existing C2 channel.

SOCKS data piggybacks on the agent's normal polling cycle (get_tasking / post_response), so no additional connections or ports are opened on the target.

### Arguments

#### action
`start`, `stop`, `stats`, or `bandwidth`.

- **start**: Start the SOCKS proxy on the specified port
- **stop**: Stop the SOCKS proxy
- **stats**: View active connections, bytes TX/RX, recent history (JSON)
- **bandwidth**: Set or disable per-connection bandwidth limit

#### port
Port for Mythic to listen on. Default: `7000`. Mythic's Docker configuration forwards port 7000 by default for proxy services.

#### bandwidth_kbs
Per-connection bandwidth limit in KB/s. Default: `0` (unlimited). Can be set at proxy start or dynamically via the `bandwidth` action. Applies to all new connections after the setting is changed.

## Usage
```
socks start [port]
socks start [port] -bandwidth_kbs 500
socks stop [port]
socks stats
socks bandwidth 500     # limit each connection to 500 KB/s
socks bandwidth 0       # disable bandwidth limiting
```

Example
```
socks start
socks start 7000
socks start 7000 -bandwidth_kbs 1024   # 1 MB/s per connection limit
socks stop 7000
socks stats
socks bandwidth 256     # limit to 256 KB/s per connection
```

Once started, configure your tools to use the proxy:
```
proxychains -q nmap -sT -p 445 10.0.0.5
proxychains curl http://10.0.0.5
```

Proxychains config (`/etc/proxychains.conf`):
```
socks5 127.0.0.1 7000
```

### UDP Relay

The SOCKS5 proxy supports UDP ASSOCIATE (RFC 1928 Section 7). This enables tools that need UDP connectivity (DNS queries, SNMP, LLMNR) to operate through the proxy. UDP datagrams are encapsulated and relayed through the existing C2 channel. Fragmented UDP packets are dropped per RFC 1928.

### Bandwidth Limiting

When bandwidth limiting is enabled, each connection is independently rate-limited using a token bucket algorithm with 2x burst allowance. This prevents any single connection from saturating the C2 channel and reduces detection risk from high-volume transfers.

## MITRE ATT&CK Mapping

- T1090 (Proxy)
- T1572 (Protocol Tunneling)
