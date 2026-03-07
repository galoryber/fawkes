+++
title = "trust"
chapter = false
weight = 116
hidden = false
+++

## Summary

Enumerate domain and forest trust relationships via LDAP with detailed analysis. Queries `trustedDomain` objects and Configuration partition crossRef objects to identify trust direction, type, transitivity, SID filtering status, encryption strength, forest topology, and potential attack paths.

Cross-platform — works on Windows, Linux, and macOS.

Complements the Windows-only trust enumeration in `net-enum` by providing cross-platform LDAP-based analysis with deeper attribute parsing and attack path identification.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| server | Yes | | Domain controller IP or hostname |
| username | No | | LDAP bind username (user@domain format) |
| password | No | | LDAP bind password |
| port | No | 389 | LDAP port |
| use_tls | No | false | Use LDAPS (port 636) |

## Usage

```
# Enumerate trusts from a child domain DC
trust -server 192.168.1.10 -username user@child.corp.local -password Pass123

# Enumerate trusts from the forest root
trust -server dc01.corp.local -username admin@corp.local -password Pass123

# Enumerate trusts using LDAPS
trust -server 192.168.1.10 -username admin@corp.local -password Pass123 -use_tls true
```

## Output Format

Returns a JSON object with forest topology and trust details, rendered as sortable tables via browser script:
```json
{
  "forest": {
    "forest_root": "sevenkingdoms.local",
    "domains": ["sevenkingdoms.local", "north.sevenkingdoms.local"]
  },
  "trusts": [
    {
      "partner": "north.sevenkingdoms.local",
      "flat_name": "NORTH",
      "direction": "Bidirectional",
      "type": "Uplevel (Active Directory)",
      "category": "Intra-Forest",
      "transitive": "Transitive (intra-forest)",
      "attributes": "WITHIN_FOREST",
      "sid": "S-1-5-21-3830354804-2748400559-49935211",
      "when_created": "2023-06-15 14:20:30 UTC",
      "risk": "Intra-forest — implicit full trust; No SID filtering — SID history attacks possible"
    }
  ]
}
```

The browser script shows two tables:
- **Forest Topology** — forest root domain and all domains in the forest
- **Domain Trusts** — trust details with risk highlighting (red for risks, orange for bidirectional)

## Forest Topology

The command queries `crossRef` objects from `CN=Partitions,CN=Configuration` to discover:
- **Forest root domain** — the top-level domain in the forest
- **All domains** — every domain in the forest hierarchy
- **Parent/child relationships** — via `trustParent` attribute

## Trust Categories

| Category | Description |
|----------|-------------|
| **Intra-Forest** | Parent/child trusts within the same AD forest. Implicit full trust — compromise any domain to escalate to all. |
| **Forest Trust** | Cross-forest trusts (FOREST_TRANSITIVE). Separate forests linked for resource access. |
| **External Trust** | Direct trusts between specific domains in different forests. Non-transitive by default. |
| **External (forced)** | Forest trust with TREAT_AS_EXTERNAL flag — SID filtering applied as if external. |
| **MIT Kerberos** | Trust with a non-AD MIT Kerberos realm. |
| **Downlevel** | Trust with a Windows NT 4.0 or Samba domain. |

## Trust Transitivity

| Value | Meaning |
|-------|---------|
| Transitive (intra-forest) | Parent/child trust — transitive within the forest |
| Transitive (forest) | Forest trust — transitive across forests |
| Non-transitive | NON_TRANSITIVE flag set |
| Non-transitive (external) | External AD trust — non-transitive by default |

## Trust Attributes

| Flag | Meaning |
|------|---------|
| WITHIN_FOREST | Intra-forest trust (parent/child or tree root) |
| FOREST_TRANSITIVE | Forest-wide trust relationship |
| NON_TRANSITIVE | Trust is not transitive (external trust) |
| SID_FILTERING | SID filtering enabled (quarantine — blocks SID history attacks) |
| TREAT_AS_EXTERNAL | Forest trust treated as external for SID filtering purposes |
| CROSS_ORGANIZATION | Selective authentication enabled — explicit permissions required |
| RC4_ENCRYPTION | Trust uses RC4 encryption |
| AES_KEYS | Trust uses AES encryption |
| NO_TGT_DELEGATION | TGT delegation disabled across organizations |
| ENABLE_TGT_DELEGATION | TGT delegation enabled across organizations |
| PIM_TRUST | Privileged Identity Management trust |

## Attack Path Analysis

The command automatically identifies exploitable trust configurations:

| Finding | Risk | Attack |
|---------|------|--------|
| Outbound trust WITHOUT SID filtering | **Critical** | Forge Golden Ticket with extra SIDs from trusted domain -> Enterprise Admin in trusting domain |
| Intra-forest trust | **Critical** | All domains in a forest implicitly trust each other. Compromise child domain -> escalate to forest root. |
| Forest trust WITHOUT SID filtering | **High** | Cross-forest SID history attack. Forge ticket with SIDs from the other forest. |
| RC4 encryption only (no AES) | **Medium** | Trust inter-realm TGTs use weak encryption — vulnerable to offline cracking. |
| TGT delegation enabled | **Medium** | Kerberos delegation across organization boundary — potential for privilege escalation. |
| Selective authentication | **Info** | Trust requires explicit Allowed-To-Authenticate permissions — limits attack surface. |

## Direction Context

Trust direction output now includes domain context to clarify the relationship:
- **Inbound** `(partner.local trusts corp.local)` — partner authenticates users from our domain
- **Outbound** `(corp.local trusts partner.local)` — we authenticate users from partner's domain
- **Bidirectional** — mutual trust in both directions

## OPSEC

- Generates LDAP queries to CN=System,<baseDN> for trustedDomain objects
- Additional query to CN=Partitions,CN=Configuration for forest topology
- Two LDAP search requests — minimal traffic
- May be logged in AD audit logs if "Audit Directory Service Access" is enabled
- Does not modify any objects

## MITRE ATT&CK Mapping

- **T1482** — Domain Trust Discovery
