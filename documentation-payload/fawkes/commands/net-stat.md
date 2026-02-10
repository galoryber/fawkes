+++
title = "net-stat"
chapter = false
weight = 110
hidden = false
+++

## Summary

List active network connections and listening ports. Shows protocol, local address, remote address, connection state, and PID.

Cross-platform — works on Windows, Linux, and macOS.

### Arguments

No arguments required.

## Usage
```
net-stat
```

### Example Output
```
47 connections

Proto  Local Address             Remote Address            State           PID
--------------------------------------------------------------------------------
TCP    0.0.0.0:135               *:*                       LISTEN          1044
TCP    0.0.0.0:445               *:*                       LISTEN          4
TCP    0.0.0.0:5985              *:*                       LISTEN          4
TCP    192.168.100.192:49721     192.168.100.184:443       ESTABLISHED     3456
TCP    192.168.100.192:49722     13.107.42.16:443          ESTABLISHED     2100
UDP    0.0.0.0:5353              *:*                       -               1876
```

Connections are sorted by state (LISTEN first, then ESTABLISHED) and then by local port.

## MITRE ATT&CK Mapping

- T1049 — System Network Connections Discovery
