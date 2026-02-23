+++
title = "dns"
chapter = false
weight = 170
hidden = false
+++

## Summary

DNS enumeration command for host resolution, record queries, and domain controller discovery. Uses pure Go `net` package — no external dependencies, no subprocess execution.

Supports custom DNS server targeting for querying internal domain DNS (e.g., Active Directory domain controllers) from non-domain-joined hosts.

## Arguments

Argument | Required | Description
---------|----------|------------
action | Yes | Query type: `resolve` (A/AAAA), `reverse` (PTR), `srv`, `mx`, `ns`, `txt`, `cname`, `all` (comprehensive), `dc` (domain controller discovery)
target | Yes | Hostname, IP address, or domain name to query
server | No | Custom DNS server IP (default: system resolver). Useful for querying AD DNS from non-domain hosts.
timeout | No | Query timeout in seconds (default: 5)

## Usage

Resolve a hostname:
```
dns -action resolve -target winterfell.north.sevenkingdoms.local -server 192.168.100.51
```

Reverse lookup an IP:
```
dns -action reverse -target 192.168.100.52
```

Discover domain controllers:
```
dns -action dc -target sevenkingdoms.local -server 192.168.100.51
```

Get all DNS records:
```
dns -action all -target north.sevenkingdoms.local -server 192.168.100.52
```

Query SRV records:
```
dns -action srv -target _ldap._tcp.sevenkingdoms.local -server 192.168.100.51
```

## Example Output

### Domain Controller Discovery
```
[*] Domain Controller discovery for sevenkingdoms.local
==================================================

[LDAP (Domain Controllers)] 1 found
  kingslanding.sevenkingdoms.local.:389 → 192.168.100.51

[Kerberos (KDC)] 1 found
  kingslanding.sevenkingdoms.local.:88 → 192.168.100.51

[Kerberos Password Change] 1 found
  kingslanding.sevenkingdoms.local.:464 → 192.168.100.51

[Global Catalog] 2 found
  kingslanding.sevenkingdoms.local.:3268 → 192.168.100.51
```

### All Records
```
[*] All DNS records for north.sevenkingdoms.local
==================================================

[A/AAAA] 1 records
  192.168.100.52

[NS] 1 records
  winterfell.north.sevenkingdoms.local.

[SRV _ldap._tcp] 1 records
  winterfell.north.sevenkingdoms.local.:389
```

## MITRE ATT&CK Mapping

- **T1018** - Remote System Discovery

{{% notice info %}}Cross-Platform — works on Windows, Linux, and macOS{{% /notice %}}
