+++
title = "lateral-check"
chapter = false
weight = 194
hidden = false
+++

## Summary

Test which lateral movement methods are available against one or more target hosts. Checks connectivity for common lateral movement protocols:

- **SMB (445)** — psexec, smb, dcom
- **WinRM HTTP (5985)** — winrm
- **WinRM HTTPS (5986)** — winrm (HTTPS)
- **RDP (3389)** — remote desktop
- **RPC/DCOM (135)** — dcom, wmi
- **SSH (22)** — ssh

Uses TCP connect checks with configurable timeout. Supports single IPs, comma-separated lists, and CIDR ranges. Maximum 256 hosts per invocation with concurrency limit of 10 simultaneous hosts.

Suggests applicable fawkes lateral movement commands based on open ports.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| hosts | Yes | - | Target hosts: single IP, comma-separated IPs, or CIDR notation (e.g., `192.168.1.0/24`) |
| timeout | No | 3 | Per-check TCP connection timeout in seconds |

## Usage

Check a single host:
```
lateral-check -hosts 192.168.1.100
```

Check multiple hosts:
```
lateral-check -hosts 192.168.1.100,192.168.1.101,192.168.1.102
```

Scan a subnet:
```
lateral-check -hosts 10.0.0.0/24 -timeout 2
```

## Output Format

Returns JSON array of host results, rendered by a browser script into a color-coded sortable table.

### JSON Structure
```json
[
  {
    "host": "192.168.1.100",
    "available": ["SMB (445)", "WinRM-HTTP (5985)", "RDP (3389)", "RPC (135)"],
    "closed": ["WinRM-HTTPS (5986)", "SSH (22)"],
    "suggested": ["psexec", "smb", "dcom", "winrm"],
    "total_open": 4
  }
]
```

### Browser Script Rendering

The browser script renders results as a color-coded sortable table:
- **Green** rows indicate hosts with **many open ports** (strong lateral movement options)
- **Red** rows indicate hosts with **no open ports** (no lateral movement available)

Columns: Host, Available Services, Closed Services, Suggested Commands, Total Open.

## MITRE ATT&CK Mapping

- **T1046** — Network Service Discovery
- **T1021** — Remote Services
