+++
title = "TCP P2P"
chapter = false
weight = 15
hidden = false
+++

## Summary

The TCP P2P profile enables peer-to-peer agent linking for internal network pivoting. A parent agent with egress (HTTP, HTTPx, or Discord) can link to child agents running the TCP profile on internal hosts. Tasks and responses route through the parent-child chain back to the Mythic server. This enables C2 communication with hosts that have no direct internet access.

{{% notice info %}}TCP P2P agents require a parent agent with an egress profile (HTTP, HTTPx, or Discord) to route traffic to Mythic. They cannot communicate with Mythic directly.{{% /notice %}}

## Architecture

```
Mythic Server ←→ [HTTP/HTTPx] Parent Agent ←→ [TCP P2P] Child Agent 1
                                            ←→ [TCP P2P] Child Agent 2
                                                         ←→ [TCP P2P] Grandchild
```

- **Parent agent**: Has an egress profile (HTTP, HTTPx, Discord) and routes messages
- **Child agent**: Listens on a TCP bind address for parent connections
- **Linking**: Parent uses the `link` command to connect to a child's bind address
- **Unlinking**: Parent uses the `unlink` command to disconnect a child

## Build Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `tcp_bind_address` | TCP address and port to listen on (e.g., `0.0.0.0:7777`) | — (required for TCP) |
| `namedpipe_bind_name` | Windows named pipe name (e.g., `msrpc-f9a1`). Uses SMB port 445. | — (optional, Windows only) |
| `AESPSK` | Pre-shared AES-256 key (must match parent for linking) | auto-generated |
| `killdate` | Agent expiration date (YYYY-MM-DD) | — |

{{% notice warning %}}The `AESPSK` must match between parent and child agents for linking to succeed. When building a TCP P2P payload, use the same encryption key as the parent payload.{{% /notice %}}

{{% notice info %}}If `namedpipe_bind_name` is set, the agent listens on a Windows named pipe instead of a TCP socket. This is Windows-only and uses SMB (port 445) under the hood.{{% /notice %}}

## Linking Workflow

### 1. Deploy the TCP P2P Agent

Build a payload with the TCP P2P profile, specifying a bind address:

- `tcp_bind_address`: `0.0.0.0:7777` (listen on all interfaces, port 7777)

Deploy and execute on the target internal host.

### 2. Link from the Parent Agent

From the parent agent's Mythic task interface, issue:

```
link -action add -host <child_ip> -port 7777
```

This connects the parent to the child's TCP listener. Once linked:
- The child agent appears as a new callback in Mythic (with an edge connecting to the parent)
- Tasks issued to the child route through the parent
- Responses flow back through the parent to Mythic

### 3. Unlink

```
unlink -connection_id <uuid>
```

Disconnects the child agent. The child continues listening and can be re-linked.

## Message Routing

All messages between the TCP P2P agent and Mythic are routed through the parent:

1. **Tasking**: Mythic → Parent (HTTP response) → Parent routes to Child (TCP)
2. **Responses**: Child → Parent (TCP) → Parent forwards to Mythic (HTTP POST)
3. **Delegates**: Messages are wrapped in delegate envelopes for multi-hop routing
4. **SOCKS**: SOCKS proxy traffic routes through the same TCP link

### Multi-Hop Chains

TCP P2P agents can link to other TCP P2P agents, creating chains:

```
Mythic ←→ Parent (HTTP) ←→ Child1 (TCP) ←→ Child2 (TCP) ←→ Child3 (TCP)
```

Each hop adds latency equal to the parent's callback interval.

## Encryption

Same AES-256-CBC encryption as other profiles:

- All TCP messages are length-prefixed: `[4-byte length][UUID + encrypted body]`
- The callback UUID is prepended to identify the agent
- Encryption uses the shared `AESPSK` key

## Connection Management

- **Auto-reconnect**: If the parent disconnects, the child continues listening for reconnection
- **Multiple children**: A parent can link to multiple TCP P2P children simultaneously
- **Edge messages**: Connection state changes (link/unlink) are reported to Mythic as edge updates
- **Channel-based routing**: Internal message routing uses Go channels for delegate, edge, and SOCKS messages

## Named Pipe Mode (Windows)

When `namedpipe_bind_name` is set, the agent listens on a Windows named pipe (`\\.\pipe\<name>`) instead of a raw TCP socket. Named pipe traffic travels over SMB (port 445), blending with normal Windows file sharing and inter-process communication.

### Named Pipe Linking

From the parent agent:

```
link -action add -host <child_ip> -pipe <pipe_name>
```

The parent connects to `\\<child_ip>\pipe\<pipe_name>` over SMB.

### Named Pipe Advantages

- **Stealthier**: SMB named pipe traffic is harder to detect than raw TCP on arbitrary ports
- **Port 445**: No additional ports needed — uses existing SMB infrastructure
- **Blends**: Legitimate Windows services use named pipes extensively (RPC, WMI, etc.)
- **Same encryption**: AES-256-CBC + HMAC-SHA256 framing is identical to TCP mode

### Named Pipe Limitations

- **Windows only**: Named pipes are a Windows-specific feature
- **SMB required**: Port 445 must be accessible between parent and child
- **Firewall rules**: SMB traffic may be filtered between network segments

## OPSEC Considerations

- TCP P2P traffic uses raw TCP sockets — no HTTP overhead on internal links
- Named pipe mode blends C2 traffic with legitimate SMB communication
- All internal traffic is AES-256 encrypted
- Bind address can be restricted to specific interfaces (e.g., `127.0.0.1:7777` for localhost only)
- Config vault encrypts C2 parameters in memory (AES-256-GCM)
- No direct internet access required for internal agents
- Named pipe creation generates ETW events — monitor for detection risk

## MITRE ATT&CK Mapping

- **T1090** — Proxy (agent acts as a relay for internal traffic)
- **T1572** — Protocol Tunneling (C2 tunneled through internal TCP connections)
- **T1573.001** — Encrypted Channel: Symmetric Cryptography
- **T1095** — Non-Application Layer Protocol (raw TCP communication)
