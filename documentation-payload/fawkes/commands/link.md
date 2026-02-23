+++
title = "link"
chapter = false
weight = 145
hidden = false
+++

## Summary

Link to a TCP P2P agent to establish a peer-to-peer connection for internal pivoting. The target agent must be built with the TCP C2 profile and be listening on the specified port.

When an egress (HTTP) agent links to a TCP child, all of the child's tasking and responses are routed through the egress agent as delegate messages. This enables internal pivoting without requiring the child agent to have direct internet access.

## Arguments

Argument | Required | Description
---------|----------|------------
host | Yes | IP address or hostname of the target P2P agent
port | Yes | TCP port the target P2P agent is listening on (default: 7777)

## Usage

```
link -host 10.0.0.2 -port 7777
```

## Example Output

```
Successfully linked to 10.0.0.2:7777 (child UUID: a1b2c3d4)
```

## MITRE ATT&CK Mapping

- **T1572** - Protocol Tunneling

{{% notice info %}}Cross-Platform — works on Windows, Linux, and macOS{{% /notice %}}
