+++
title = "rpfwd"
chapter = false
weight = 201
hidden = false
+++

## Summary

Reverse port forward -- the agent listens on a local port on the target machine, and Mythic routes incoming connections to a remote target that is accessible from the Mythic server (or operator's network). This is useful for exposing internal services through the agent's callback without requiring the agent to make outbound connections to the target.

Traffic flows through the existing C2 channel, so no additional ports are opened on the target beyond the listening port.

### Arguments

#### action
`start` or `stop` the reverse port forward.

#### port
The port for the agent to listen on (on the target machine). This is the port that local or network clients will connect to.

#### remote_ip
The IP address of the remote target that Mythic should route connections to. This host must be accessible from the Mythic server or operator's network.

#### remote_port
The port on the remote target to connect to.

## Usage
```
rpfwd start <port> <remote_ip> <remote_port>
rpfwd stop <port>
```

Examples
```
rpfwd start 8080 10.0.0.1 80
rpfwd start 3389 192.168.1.100 3389
rpfwd stop 8080
```

**Traffic flow:**
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

This is cross-platform and works on Linux, macOS, and Windows.

## MITRE ATT&CK Mapping

- T1090 (Proxy)
