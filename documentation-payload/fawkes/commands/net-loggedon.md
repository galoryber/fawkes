+++
title = "net-loggedon"
chapter = false
weight = 118
hidden = false
+++

{{% notice info %}}Windows Only{{% /notice %}}

## Summary

Enumerates users currently logged on to a local or remote machine using the `NetWkstaUserEnum` Win32 API (level 1). Shows the username, logon domain, and logon server for each active session.

This is a key reconnaissance command for identifying which users are active on target machines, helping operators find high-value targets (domain admins, service accounts) and plan lateral movement.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| target   | No       | (local) | Target hostname or IP address. Leave blank to enumerate users on the local machine. |

## Usage

```
# Enumerate logged-on users on local machine
net-loggedon

# Enumerate logged-on users on a remote host
net-loggedon -target dc01.domain.local

# Enumerate by IP
net-loggedon -target 192.168.1.10
```

### Output Fields

| Field | Description |
|-------|-------------|
| Username | The logged-on user's name |
| Logon Domain | The domain or machine the user authenticated against |
| Logon Server | The server that processed the logon request |

### Notes

- Remote enumeration requires appropriate permissions (typically admin on the target)
- Error 5 (ACCESS_DENIED) on remote targets is expected when running without admin privileges
- Results include both interactive and network logon sessions

## MITRE ATT&CK Mapping

- **T1033** - System Owner/User Discovery
