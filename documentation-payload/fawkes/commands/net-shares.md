+++
title = "net-shares"
chapter = false
weight = 145
hidden = false
+++

## Summary

Enumerates network shares on the local machine, remote hosts, or lists mapped network drives. Uses `net.exe` for all operations.

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Type | Description |
|----------|----------|------|-------------|
| action | Yes | ChooseOne | `local` - list shares on this machine, `remote` - list shares on target, `mapped` - list mapped network drives |
| target | No | String | Hostname or IP for remote action (e.g., DC01, 192.168.1.1) |

## Usage

List local shares:
```
net-shares -action local
```

List shares on a remote host:
```
net-shares -action remote -target DC01
```

List mapped network drives:
```
net-shares -action mapped
```

## MITRE ATT&CK Mapping

- **T1135** - Network Share Discovery
