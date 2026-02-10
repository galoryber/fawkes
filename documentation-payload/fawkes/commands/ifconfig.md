+++
title = "ifconfig"
chapter = false
weight = 108
hidden = false
+++

## Summary

List all network interfaces and their addresses. Shows interface name, flags (up/down/loopback/etc.), MTU, MAC address, and IPv4/IPv6 addresses with subnet masks.

Cross-platform — works on Windows, Linux, and macOS.

### Arguments

No arguments required.

## Usage
```
ifconfig
```

### Example Output
```
Ethernet: flags=<up|broadcast|multicast> mtu 1500
    ether 00:0c:29:ab:cd:ef
    inet 192.168.100.192/24
    inet6 fe80::20c:29ff:feab:cdef/64

Loopback Pseudo-Interface 1: flags=<up|loopback|multicast> mtu -1
    inet 127.0.0.1/8
    inet6 ::1/128
```

## MITRE ATT&CK Mapping

- T1016 — System Network Configuration Discovery
