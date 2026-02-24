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
action | Yes | Query type: `resolve` (A/AAAA), `reverse` (PTR), `srv`, `mx`, `ns`, `txt`, `cname`, `all` (comprehensive), `dc` (domain controller discovery), `zone-transfer` (AXFR)
target | Yes | Hostname, IP address, or domain name to query
server | No | Custom DNS server IP (default: system resolver). **Required** for `zone-transfer` action.
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

Attempt a zone transfer (AXFR):
```
dns -action zone-transfer -target sevenkingdoms.local -server 192.168.100.51
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

### Zone Transfer (AXFR)
```
[*] Zone transfer (AXFR) for testzone.lab from 10.0.0.2:53
==================================================
  testzone.lab                             SOA      ns1.testzone.lab admin.testzone.lab serial=2024010101
  testzone.lab                             TXT      "v=spf1 mx -all"  TTL=86400
  testzone.lab                             MX       mail.testzone.lab pref=10  TTL=86400
  testzone.lab                             NS       ns1.testzone.lab  TTL=86400
  testzone.lab                             A        10.0.0.1  TTL=86400
  _ldap._tcp.testzone.lab                  SRV      dc1.testzone.lab:389 priority=0 weight=100  TTL=86400
  dc1.testzone.lab                         A        10.0.0.50  TTL=86400
  ftp.testzone.lab                         CNAME    www.testzone.lab  TTL=86400
  www.testzone.lab                         A        10.0.0.10  TTL=86400
  testzone.lab                             SOA      ns1.testzone.lab admin.testzone.lab serial=2024010101

[+] Zone transfer complete: 10 records
```

When zone transfer is refused (common in production):
```
[!] Zone transfer refused: REFUSED
[*] Zone transfers are typically restricted to authorized secondary DNS servers
```

## Notes

- **Zone transfer** uses raw DNS wire protocol over TCP (no external dependencies). The `-server` parameter is required because AXFR bypasses the system resolver.
- Parses A, AAAA, NS, CNAME, SOA, MX, TXT, and SRV record types. Handles DNS compression pointers.
- Zone transfers are often restricted in production environments. Getting a REFUSED response is expected for properly configured DNS servers.

## MITRE ATT&CK Mapping

- **T1018** - Remote System Discovery

{{% notice info %}}Cross-Platform — works on Windows, Linux, and macOS{{% /notice %}}
