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

### Output Fields

**Level 502 (Admin):**
| Field | Description |
|-------|-------------|
| Client | Client IP/hostname connected to the server |
| User | Username of the connected session |
| Opens | Number of open files/resources |
| Time | Duration of the connection |
| Idle | Time since last activity |
| Transport | Network transport name |

**Level 10 (Non-Admin Fallback):**
| Field | Description |
|-------|-------------|
| Client | Client IP/hostname |
| User | Username |
| Connected | Duration of the connection |
| Idle | Time since last activity |

## MITRE ATT&CK Mapping

- **T1049** - System Network Connections Discovery
