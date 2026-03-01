+++
title = "certstore"
chapter = false
weight = 158
hidden = false
+++

## Summary

Enumerate Windows certificate stores to find code signing certificates, client authentication certificates, and certificates with associated private keys. Searches both CurrentUser and LocalMachine hive locations across standard stores (MY, ROOT, CA, Trust, TrustedPeople).

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | list | Action: `list` (enumerate all) or `find` (search with filter) |
| store | No | all | Certificate store to enumerate: `MY`, `ROOT`, `CA`, `Trust`, `TrustedPeople`, or blank for all |
| filter | For find | — | Case-insensitive substring match against subject, issuer, thumbprint, or serial number |

### Stores

| Store | Description |
|-------|-------------|
| MY | Personal certificates (client auth, code signing) |
| ROOT | Trusted Root Certificate Authorities |
| CA | Intermediate Certificate Authorities |
| Trust | Enterprise Trust |
| TrustedPeople | Trusted People |

## Usage

```
# List all certificates across all stores
certstore

# List certificates in the Personal store only
certstore -action list -store MY

# Search for certificates by subject/issuer name
certstore -action find -filter "Microsoft"

# Search for a specific certificate by thumbprint
certstore -action find -filter "8F:43:28:8A"

# Search for code signing certs
certstore -action find -filter "Code Signing"
```

### Browser Script

Output is rendered as a sortable table in the Mythic UI with columns: Subject, Issuer, Store, Location, Not Before, Not After, Has Private Key, Thumbprint. Expired certificates are highlighted red; certificates with private keys are highlighted orange.

### Example Output (JSON)
```json
[
  {"subject":"Microsoft Root Certificate Authority","issuer":"Microsoft Root Certificate Authority","serial_number":"79ad16a14aa0a5ad","not_before":"2001-05-10","not_after":"2021-05-10","expired":true,"thumbprint":"CC:B3:...:A4","has_private_key":false,"store":"ROOT","location":"LocalMachine"},
  {"subject":"My Code Signing Cert","issuer":"DigiCert","thumbprint":"AB:12:...:CD","has_private_key":true,"store":"MY","location":"CurrentUser"}
]
```

## Operational Notes

- Certificates with private keys in the `MY` store are high-value targets for credential theft
- Self-signed certificates with private keys may indicate custom CA or code signing capabilities
- LocalMachine stores may require elevated privileges to enumerate fully
- The private key check uses `CRYPT_ACQUIRE_SILENT_FLAG` to avoid UI prompts
- Pair with `adcs` for Active Directory Certificate Services enumeration

## MITRE ATT&CK Mapping

- **T1552.004** — Unsecured Credentials: Private Keys
- **T1649** — Steal or Forge Authentication Certificates
