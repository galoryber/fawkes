+++
title = "link"
chapter = false
weight = 145
hidden = false
+++

## Summary

Link to a P2P agent via TCP or named pipe to establish a peer-to-peer connection for internal pivoting. The target agent must be built with the TCP C2 profile and be listening on the specified port or named pipe.

When an egress (HTTP) agent links to a child, all of the child's tasking and responses are routed through the egress agent as delegate messages. This enables internal pivoting without requiring the child agent to have direct internet access.

**Named pipe mode** uses SMB (port 445) to connect, which blends with normal Windows file sharing traffic and is stealthier than raw TCP connections.

## Arguments

Argument | Required | Description
---------|----------|------------
connection_type | No | P2P transport: `tcp` (default) or `namedpipe` (Windows, uses SMB port 445)
host | Yes | IP address or hostname of the target P2P agent
port | No | TCP port the target P2P agent is listening on (default: 7777, TCP mode only)
pipe_name | No | Named pipe name without `\\.\pipe\` prefix (e.g., `msrpc-f9a1`, namedpipe mode only)

## Usage

**TCP link (default):**

```
link -host 10.0.0.2 -port 7777
```

**Named pipe link (Windows):**

```
link -connection_type namedpipe -host 10.0.0.2 -pipe_name msrpc-f9a1
```

## Example Output

```
Successfully linked to 10.0.0.2:7777 via tcp (child UUID: a1b2c3d4)
```

```
Successfully linked to \\10.0.0.2\pipe\msrpc-f9a1 via namedpipe (child UUID: a1b2c3d4)
```

## OPSEC Notes

- **TCP mode**: TCP connection establishment generates network telemetry. Firewall rules and network monitoring may detect the lateral connection.
- **Named pipe mode**: Uses SMB (port 445) which blends with normal Windows traffic. However, Sysmon Event ID 17/18 (PipeEvent) and ETW events from Microsoft-Windows-SMBClient will be logged if configured.

## MITRE ATT&CK Mapping

- **T1572** - Protocol Tunneling

{{% notice info %}}TCP mode: Cross-Platform (Windows, Linux, macOS). Named pipe mode: Windows only.{{% /notice %}}
