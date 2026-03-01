+++
title = "trust"
chapter = false
weight = 116
hidden = false
+++

## Summary

Enumerate domain and forest trust relationships via LDAP. Queries `trustedDomain` objects to identify trust direction, type, SID filtering status, and potential attack paths for lateral movement across domain and forest boundaries.

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

Returns a JSON array rendered as a sortable table via browser script:
```json
[
  {
    "partner": "north.sevenkingdoms.local",
    "flat_name": "NORTH",
    "direction": "Bidirectional",
    "type": "Uplevel",
    "category": "Intra-Forest",
    "attributes": "WITHIN_FOREST",
    "sid": "S-1-5-21-3830354804-2748400559-49935211",
    "risk": "Intra-forest implicit full trust; No SID filtering — SID history attacks possible"
  },
  {
    "partner": "essos.local",
    "flat_name": "ESSOS",
    "direction": "Bidirectional",
    "type": "Uplevel",
    "category": "Forest",
    "attributes": "FOREST_TRANSITIVE | TREAT_AS_EXTERNAL",
    "sid": "S-1-5-21-69387547-3003948751-3466758987",
    "risk": "Forest trust without SID filtering — cross-forest SID history attack"
  }
]
```

The browser script highlights entries with risks in red, bidirectional trusts in orange, and provides copyable partner domain names.

## Trust Categories

| Category | Description |
|----------|-------------|
| **Intra-Forest** | Parent/child trusts within the same AD forest. Implicit full trust — compromise any domain to escalate to all. |
| **Forest Trust** | Cross-forest trusts (FOREST_TRANSITIVE). Separate forests linked for resource access. |
| **External Trust** | Direct trusts between specific domains in different forests. Non-transitive by default. |

## Trust Attributes

| Flag | Meaning |
|------|---------|
| WITHIN_FOREST | Intra-forest trust (parent/child or tree root) |
| FOREST_TRANSITIVE | Forest-wide trust relationship |
| NON_TRANSITIVE | Trust is not transitive (external trust) |
| SID_FILTERING | SID filtering enabled (quarantine — blocks SID history attacks) |
| TREAT_AS_EXTERNAL | Forest trust treated as external for SID filtering purposes |
| RC4_ENCRYPTION | Trust uses RC4 encryption |
| AES_KEYS | Trust uses AES encryption |

## Attack Path Analysis

The command automatically identifies exploitable trust configurations:

| Finding | Risk | Attack |
|---------|------|--------|
| Outbound trust WITHOUT SID filtering | **Critical** | Forge Golden Ticket with extra SIDs from trusted domain → Enterprise Admin in trusting domain |
| Intra-forest trust | **Critical** | All domains in a forest implicitly trust each other. Compromise child domain → escalate to forest root. |
| Forest trust WITHOUT SID filtering | **High** | Cross-forest SID history attack. Forge ticket with SIDs from the other forest. |

## OPSEC

- Generates LDAP queries to CN=System,<baseDN> for trustedDomain objects
- Single LDAP search request — minimal traffic
- May be logged in AD audit logs if "Audit Directory Service Access" is enabled
- Does not modify any objects

## MITRE ATT&CK Mapping

- **T1482** — Domain Trust Discovery
