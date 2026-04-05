+++
title = "rpfwd"
chapter = false
weight = 201
hidden = false
+++

## Summary

Port forwarding through the agent with two modes:

**Reverse (start):** The agent listens on a local port, and Mythic routes incoming connections to a remote target accessible from the Mythic server. Useful for exposing Mythic-accessible services to hosts on the target network.

**Forward:** The agent listens on a local port AND connects to an internal target on the agent's network. Useful for accessing internal services (web UIs, databases, management interfaces) via the agent as a jump host. The operator typically reaches the listening port through an existing SOCKS proxy. No rpfwd data traverses C2 — the relay is entirely local to the agent.

Both modes are cross-platform (Linux, macOS, Windows).

### Arguments

#### action
- `start` — Reverse port forward (Mythic routes to remote target)
- `forward` — Forward port forward (agent relays to internal target)
- `stop` — Stop any port forward on the specified port

#### port
The port for the agent to listen on (on the target machine).

#### remote_ip
*(start only)* The IP address of the remote target that Mythic should route connections to. Must be accessible from the Mythic server.

#### remote_port
*(start only)* The port on the remote target to connect to.

#### target_ip
*(forward only)* The IP address of the internal target to relay connections to. Must be accessible from the agent's host.

#### target_port
*(forward only)* The port on the internal target to connect to.

#### bind_address
*(forward only, optional)* The address to bind the listener on. Default: `0.0.0.0` (all interfaces). Use `127.0.0.1` to restrict to localhost only.

## Usage
```
rpfwd start <port> <remote_ip> <remote_port>
rpfwd forward <port> <target_ip> <target_port> [bind_address]
rpfwd stop <port>
```

Examples
```
# Reverse: expose Mythic-accessible web server to target network
rpfwd start 8080 10.0.0.1 80

# Forward: access internal database through agent
rpfwd forward 3306 10.10.10.50 3306

# Forward: access internal web UI, bind to localhost only
rpfwd forward 8443 192.168.1.100 443 127.0.0.1

# Stop any port forward
rpfwd stop 8080
```

**Reverse port forward traffic flow:**
```
Client on target network
        |
        v
  Agent (listening on port 8080)
        |
     C2 channel
        |
        v
  Mythic Server
        |
        v
  Remote target 10.0.0.1:80
```

**Forward port forward traffic flow:**
```
Operator (via SOCKS proxy)
        |
     C2 channel (SOCKS)
        |
        v
  Agent (listening on port 3306)
        |
     Local TCP relay
        |
        v
  Internal target 10.10.10.50:3306
```

## MITRE ATT&CK Mapping

- T1090 (Proxy)
