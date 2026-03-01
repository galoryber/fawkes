+++
title = "klist"
chapter = false
weight = 144
hidden = false
+++

## Summary

Enumerate, filter, dump, purge, and import Kerberos tickets. Supports Pass-the-Ticket (T1550.003) by injecting forged or extracted tickets into the ticket cache.

On **Windows**, uses the LSA (Local Security Authority) API via `secur32.dll` to interact with the Kerberos authentication package directly. Supports listing cached tickets with metadata, dumping tickets as base64-encoded kirbi, purging the ticket cache, and importing kirbi tickets via `KERB_SUBMIT_TKT_REQUEST`.

On **Linux/macOS**, parses the Kerberos ccache file (typically `/tmp/krb5cc_<uid>` or as specified by `$KRB5CCNAME`). Supports v3 and v4 ccache formats. Purge deletes the ccache file. Dump exports the entire ccache as base64. Import writes a ccache file and sets `KRB5CCNAME`.

## Arguments

Argument | Required | Description
---------|----------|------------
action | No | Action to perform: `list` (default), `purge`, `dump`, or `import`
server | No | Filter tickets by server name (substring match, e.g., `krbtgt`)
ticket | No | Base64-encoded ticket data for import (kirbi on Windows, ccache on Linux/macOS)
path | No | Output path for import on Linux/macOS (default: `/tmp/krb5cc_<uid>`)

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

Import a ticket for Pass-the-Ticket (use output from `ticket` command):
```
klist -action import -ticket <base64_ccache_data>
```

Import with custom path:
```
klist -action import -ticket <base64> -path /tmp/custom_ccache
```

### Forge + Import Workflow

1. Forge a Golden Ticket:
```
ticket -action forge -realm DOMAIN.COM -username admin -domain_sid S-1-5-21-... -key <krbtgt_key> -format ccache
```

2. Copy the base64 output and import it:
```
klist -action import -ticket <base64_from_step_1>
```

3. Verify the imported ticket:
```
klist -action list
```

## Output Format

The `list` action returns a JSON array rendered as a sortable table via browser script:
```json
[
  {
    "index": 0,
    "client": "user@DOMAIN.COM",
    "server": "krbtgt/DOMAIN.COM@DOMAIN.COM",
    "encryption": "AES256-CTS (etype 18)",
    "flags": "forwardable, renewable, initial, pre-authent",
    "start": "2026-02-24 08:00:00",
    "end": "2026-02-24 18:00:00",
    "renew": "2026-03-03 08:00:00",
    "status": "valid"
  }
]
```

The browser script highlights TGT tickets (`krbtgt`) in blue and expired tickets in red. Other actions (`dump`, `purge`, `import`) return plain text responses.

## MITRE ATT&CK Mapping

- **T1558** - Steal or Forge Kerberos Tickets
- **T1550.003** - Use Alternate Authentication Material: Pass the Ticket

{{% notice info %}}Cross-Platform — works on Windows, Linux, and macOS{{% /notice %}}
