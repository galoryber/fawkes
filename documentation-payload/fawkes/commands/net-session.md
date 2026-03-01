+++
title = "net-session"
chapter = false
weight = 117
hidden = false
+++

{{% notice info %}}Windows Only{{% /notice %}}

## Summary

Enumerates active SMB sessions on a local or remote machine using the `NetSessionEnum` Win32 API. This is useful for discovering which users have active connections to file shares, identifying lateral movement opportunities, and mapping network activity.

The command attempts **level 502** first (full detail including transport info, requires admin privileges) and automatically falls back to **level 10** (basic info, no admin required).

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| target   | No       | (local) | Target hostname or IP address. Leave blank to enumerate sessions on the local machine. |

## Usage

```
# Enumerate sessions on local machine
net-session

# Enumerate sessions on a remote host
net-session -target dc01.domain.local

# Enumerate sessions by IP
net-session -target 192.168.1.10
```

### Browser Script

Output is rendered as a sortable table in the Mythic UI. Level 502 shows columns: Client, User, Opens, Time, Idle, Transport. Level 10 fallback shows: Client, User, Time, Idle.

### Example Output (JSON)
```json
[
  {"client":"\\\\192.168.1.50","user":"admin","opens":3,"time":"2h15m","idle":"5m30s","transport":"\\Device\\NetBT_Tcpip"},
  {"client":"\\\\192.168.1.51","user":"svc_sql","opens":1,"time":"45m12s","idle":"10s"}
]
```

## MITRE ATT&CK Mapping

- **T1049** - System Network Connections Discovery
