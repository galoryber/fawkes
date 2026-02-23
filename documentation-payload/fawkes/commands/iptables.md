+++
title = "iptables"
chapter = false
weight = 110
hidden = false
+++

## Summary

Linux firewall enumeration and rule management. Queries firewall status from `/proc`, enumerates iptables/ip6tables rules, checks nftables and ufw, and supports adding/deleting/flushing rules. Complements the Windows `firewall` command for cross-platform firewall awareness.

{{% notice info %}}Linux Only{{% /notice %}}

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | Yes | `status`: IP forwarding, tables, ufw status. `rules`: list all rules. `nat`: NAT rules only. `add`/`delete`/`flush`: modify rules. |
| rule | Add/Delete | iptables rule arguments (e.g., `-A INPUT -p tcp --dport 4444 -j ACCEPT`) |
| table | No | iptables table: `filter` (default), `nat`, `mangle`, `raw`, `security` |
| chain | No | Chain name for flush action (`INPUT`, `OUTPUT`, `FORWARD`, etc.) |

## Usage

```
# Check firewall status (IP forwarding, tables, ufw, conntrack)
iptables -action status

# List all filter rules
iptables -action rules

# List NAT rules
iptables -action nat

# List rules from a specific table
iptables -action rules -table mangle

# Add a rule to allow inbound traffic on port 4444
iptables -action add -rule "-A INPUT -p tcp --dport 4444 -j ACCEPT"

# Delete a rule
iptables -action delete -rule "-D INPUT -p tcp --dport 4444 -j ACCEPT"

# Flush all rules in a chain
iptables -action flush -chain INPUT

# Flush all rules in all chains
iptables -action flush
```

## Status Output

The `status` action reports:
- **IP Forwarding** — IPv4/IPv6 forwarding status from `/proc/sys/net/ipv4/ip_forward`
- **iptables Tables** — Active tables from `/proc/net/ip_tables_names`
- **nftables** — Tables from `nft list tables` (if available)
- **ufw** — Firewall status from `ufw status` (if available)
- **Connection Tracking** — Active/max connections from `/proc/sys/net/netfilter/nf_conntrack_*`

## OPSEC Considerations

- `status` reads from `/proc` (no subprocess for status information)
- `rules`, `nat`, `add`, `delete`, `flush` invoke `iptables`/`ip6tables`/`nft` binaries
- Reading rules requires root or `CAP_NET_ADMIN` — non-root will see "Permission denied"
- Modifying rules requires root
- Rule changes are **not persistent** across reboots unless saved with `iptables-save`
- Flushing rules can disrupt network connectivity — use with caution

## MITRE ATT&CK Mapping

- **T1562.004** — Impair Defenses: Disable or Modify System Firewall
