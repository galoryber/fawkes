+++
title = "klist"
chapter = false
weight = 144
hidden = false
+++

## Summary

Enumerate, filter, dump, and purge Kerberos tickets from the current logon session's ticket cache.

On **Windows**, uses the LSA (Local Security Authority) API via `secur32.dll` to interact with the Kerberos authentication package directly. Supports listing cached tickets with metadata, dumping tickets as base64-encoded kirbi for pass-the-ticket, and purging the ticket cache.

On **Linux/macOS**, parses the Kerberos ccache file (typically `/tmp/krb5cc_<uid>` or as specified by `$KRB5CCNAME`). Supports v3 and v4 ccache formats. Purge deletes the ccache file. Dump exports the entire ccache as base64.

## Arguments

Argument | Required | Description
---------|----------|------------
action | No | Action to perform: `list` (default), `purge`, or `dump`
server | No | Filter tickets by server name (substring match, e.g., `krbtgt`)

## Usage

List all cached Kerberos tickets:
```
klist -action list
```

List tickets with server name filter:
```
klist -action list -server krbtgt
```

Dump tickets as base64 kirbi (Windows) or ccache (Linux/macOS):
```
klist -action dump
```

Purge all cached tickets:
```
klist -action purge
```

## Example Output

```
=== Kerberos Ticket Cache ===

Cached tickets: 3

  [0] Client:  user@DOMAIN.COM
      Server:  krbtgt/DOMAIN.COM@DOMAIN.COM
      Encrypt: AES256-CTS (etype 18)
      Flags:   forwardable, renewable, initial, pre-authent
      Start:   2026-02-24 08:00:00
      End:     2026-02-24 18:00:00
      Renew:   2026-03-03 08:00:00

  [1] Client:  user@DOMAIN.COM
      Server:  cifs/fileserver.domain.com@DOMAIN.COM
      Encrypt: AES256-CTS (etype 18)
      Flags:   forwardable, renewable, pre-authent
      Start:   2026-02-24 08:05:12
      End:     2026-02-24 18:05:12
      Renew:   2026-03-03 08:00:00
```

## MITRE ATT&CK Mapping

- **T1558** - Steal or Forge Kerberos Tickets
- **T1550.003** - Use Alternate Authentication Material: Pass the Ticket

{{% notice info %}}Cross-Platform — works on Windows, Linux, and macOS{{% /notice %}}
