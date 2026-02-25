+++
title = "adcs"
chapter = false
weight = 105
hidden = false
+++

## Summary

Enumerate Active Directory Certificate Services (ADCS) and detect vulnerable certificate templates. Queries the PKI configuration via LDAP to find Certificate Authorities, list templates, and identify ESC1-ESC4 vulnerabilities.

Includes binary security descriptor parsing to identify which users/groups can enroll in each template, enabling accurate low-privilege exploitation detection.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `action` | Yes | `find` | `cas`: list Certificate Authorities, `templates`: list all templates, `find`: find vulnerable templates (ESC1-ESC4) |
| `server` | Yes | | Domain controller IP or hostname |
| `username` | No | | Bind username in UPN format (e.g., `user@domain.local`) |
| `password` | No | | Bind password |
| `port` | No | 389/636 | LDAP port (389 for LDAP, 636 for LDAPS) |
| `use_tls` | No | false | Use LDAPS (TLS) instead of plain LDAP |

## Vulnerability Checks

| ESC | Name | Detection Criteria |
|-----|------|-------------------|
| ESC1 | Enrollee Supplies Subject | `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` + Client Auth EKU + low-priv enrollment + no manager approval |
| ESC2 | Any Purpose / SubCA | Any Purpose EKU or no EKU (SubCA) + low-priv enrollment |
| ESC3 | Certificate Request Agent | Certificate Request Agent EKU + low-priv enrollment |
| ESC4 | Template ACL Abuse | Low-priv user has WriteDACL/WriteOwner/GenericAll on template |

Low-privilege groups detected: Everyone, Authenticated Users, BUILTIN\Users, Domain Users (RID 513), Domain Computers (RID 515).

## Usage

```
# Find vulnerable templates (recommended first action)
adcs -action find -server 192.168.1.10 -username user@domain.local -password Pass123

# List all Certificate Authorities
adcs -action cas -server dc01 -username user@domain.local -password Pass123

# List all certificate templates with security-relevant attributes
adcs -action templates -server dc01 -username user@domain.local -password Pass123

# Use LDAPS
adcs -action find -server dc01 -username user@domain.local -password Pass123 -use_tls true
```

## Example Output

### `find` action
```
ADCS Vulnerability Assessment
============================================================
CAs: 1 | Templates: 40 | Published: 18

[!] ESC1 (CA: ESSOS-CA)
    ESC1: Enrollee supplies subject + auth EKU + low-priv enrollment (Domain Users)
    EKUs: Client Authentication

[!] ESC2 (CA: ESSOS-CA)
    ESC2: Any purpose/SubCA EKU + low-priv enrollment (Domain Users)
    EKUs: Any Purpose

Found 2 vulnerable template(s)
```

### `cas` action
```
Certificate Authorities (1 found)
============================================================

[CA 1] ESSOS-CA
  DNS Name:    braavos.essos.local
  CA DN:       CN=ESSOS-CA, DC=essos, DC=local
  Templates:   18 published
    - Administrator
    - EFSRecovery
    - ...
```

## Notes

- **Cross-platform**: Works from Windows, Linux, and macOS agents — only needs LDAP access to a domain controller.
- **Security descriptor parsing**: Parses the binary `nTSecurityDescriptor` attribute to determine enrollment permissions for each template.
- **ESC6/ESC8**: These vulnerabilities require checking CA registry settings (EDITF_ATTRIBUTESUBJECTALTNAME2) and HTTP enrollment endpoints, which are not available via LDAP. Use `certutil -v -dstemplate` or Certipy on-host for these checks.
- **Published templates only**: The `find` action only checks templates that are published by at least one CA — unpublished templates cannot be exploited.

## MITRE ATT&CK Mapping

- **T1649** — Steal or Forge Authentication Certificates
