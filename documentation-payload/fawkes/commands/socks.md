+++
title = "socks"
chapter = false
weight = 103
hidden = false
+++

## Summary

Start or stop a SOCKS5 proxy through the agent's callback. Mythic handles SOCKS5 authentication on the server side. The agent parses SOCKS5 CONNECT requests, establishes TCP connections to the target, and relays data bidirectionally through the existing C2 channel.

SOCKS data piggybacks on the agent's normal polling cycle (get_tasking / post_response), so no additional connections or ports are opened on the target.

### Arguments

#### action
`start` or `stop` the SOCKS proxy.

#### port
Port for Mythic to listen on. Default: `7000`. Mythic's Docker configuration forwards port 7000 by default for proxy services.

## Usage
```
socks start [port]
socks stop [port]
```

Example
```
socks start
socks start 7000
socks stop 7000
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

## MITRE ATT&CK Mapping

- T1090
