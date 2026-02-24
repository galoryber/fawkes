+++
title = "domain-policy"
chapter = false
weight = 103
hidden = false
+++

## Summary

Enumerate Active Directory domain password policy, lockout policy, and fine-grained password policies (FGPPs) via LDAP. Essential pre-spray reconnaissance to understand lockout thresholds before running password spraying attacks.

Cross-platform — works from Windows, Linux, and macOS agents.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | Yes | What to query: `password`, `lockout`, `fgpp`, or `all` |
| server | Yes | Domain Controller IP/hostname |
| username | No | LDAP bind username (UPN format: `user@domain.local`) |
| password | No | LDAP bind password |
| base_dn | No | LDAP base DN (auto-detected from RootDSE if not specified) |
| port | No | LDAP port (default: 389, or 636 for LDAPS) |
| use_tls | No | Use LDAPS (TLS) connection (default: false) |

## Actions

### password
Queries the default domain password policy: minimum length, history depth, maximum/minimum age, and complexity requirements.

### lockout
Queries the default domain lockout policy: threshold, duration, and observation window. Provides spray-safe recommendations (max attempts and suggested delay).

### fgpp
Queries Fine-Grained Password Policies (FGPPs) from `CN=Password Settings Container`. Shows per-PSO settings including precedence, policy details, and which users/groups the policy applies to. Requires Windows Server 2008+ domain functional level.

### all
Queries all of the above — default password policy, lockout policy, and FGPPs.

## Usage

### Full policy enumeration
```
domain-policy -action all -server dc01 -username user@corp.local -password Pass123
```

### Lockout policy only (pre-spray check)
```
domain-policy -action lockout -server 192.168.1.1 -username admin@corp.local -password Admin1
```

### Fine-grained password policies
```
domain-policy -action fgpp -server dc01 -username user@corp.local -password Pass1
```

### LDAPS connection
```
domain-policy -action all -server dc01 -username user@corp.local -password Pass1 -use_tls true
```

## Output

### Password Policy
- Minimum Password Length
- Password History Length
- Maximum Password Age (days or "Never")
- Minimum Password Age
- Password Complexity (enabled/disabled, reversible encryption)

### Lockout Policy
- Lockout Threshold (attempts before lockout)
- Lockout Duration (how long account stays locked)
- Observation Window (counter reset interval)
- **Spray Recommendation**: Maximum safe attempts per window and suggested delay

### Fine-Grained Password Policies
- PSO name and precedence
- Per-policy password/lockout settings
- Applied-to users and groups

## OPSEC Considerations

- Uses standard LDAP queries against the domain root object — low-noise operation
- Authenticated bind required for most AD configurations (anonymous bind may be rejected)
- Query targets the domain root DN, not individual user objects
- No user enumeration or password validation performed
- Recommended as first step before any password spraying operation

## MITRE ATT&CK Mapping

- T1201 — Password Policy Discovery
