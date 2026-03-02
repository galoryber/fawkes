+++
title = "cert-check"
chapter = false
weight = 157
hidden = false
+++

## Summary

Inspect TLS certificates on remote hosts. Identifies certificate authorities, self-signed certificates, certificate expiry, Subject Alternative Names (SANs), TLS version, cipher suites, and SHA256 fingerprints. Useful for service discovery, identifying internal PKI infrastructure, and detecting misconfigured TLS.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| host | Yes | — | Target hostname or IP address |
| port | No | 443 | TLS port to connect to |
| timeout | No | 10 | Connection timeout in seconds |

## Usage

```
# Check certificate on default HTTPS port
cert-check -host example.com

# Check certificate on a custom port
cert-check -host 192.168.1.1 -port 8443

# Check internal service with short timeout
cert-check -host intranet.corp.local -port 443 -timeout 5

# Check LDAPS certificate
cert-check -host dc01.corp.local -port 636
```

### Example Output

```
=== TLS Certificate Check: intranet.corp.local:443 ===

TLS Version:   TLS 1.2
Cipher Suite:  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
Certificates:  2 in chain

--- Leaf Certificate ---
  Subject:     CN=intranet.corp.local,O=Corp Inc
  Issuer:      CN=Corp Internal CA,O=Corp Inc
  Not Before:  2025-01-15T00:00:00Z
  Not After:   2026-01-15T23:59:59Z
  Validity:    OK (319 days remaining)
  SANs:
    DNS: intranet.corp.local
    DNS: *.corp.local
    IP:  10.0.0.50
  Host Match:  OK
  Sig Algo:    SHA256-RSA
  Serial:      123456789
  SHA256:      a1b2c3d4...

--- Certificate #2 (CA) ---
  Subject:     CN=Corp Internal CA,O=Corp Inc
  Issuer:      CN=Corp Internal CA,O=Corp Inc
  Self-Signed: YES
  Not Before:  2020-01-01T00:00:00Z
  Not After:   2030-12-31T23:59:59Z
  Validity:    OK (1766 days remaining)
  Sig Algo:    SHA256-RSA
  CA:          YES
  Serial:      1
  SHA256:      e5f6a7b8...
```

## Operational Notes

- Connects with `InsecureSkipVerify` to inspect all certificates regardless of trust
- Self-signed certificates are flagged — common on internal services
- Expired or not-yet-valid certificates are highlighted
- SANs reveal hostnames and IPs the certificate covers — useful for reconnaissance
- Certificate chain is displayed (leaf + intermediate/root CAs)
- SHA256 fingerprints can be used for certificate pinning validation
- Pair with `certstore` (Windows) for local certificate enumeration
- Pair with `adcs` for Active Directory Certificate Services discovery

## MITRE ATT&CK Mapping

- **T1590.001** — Gather Victim Network Information: Domain Properties
