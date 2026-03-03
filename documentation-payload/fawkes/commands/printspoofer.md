+++
title = "printspoofer"
chapter = false
weight = 199
hidden = false
+++

## Summary

PrintSpoofer privilege escalation — one-step SeImpersonate to SYSTEM via the Print Spooler service.

{{% notice info %}}Windows Only{{% /notice %}}

Implements the [PrintSpoofer technique](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) by creating a named pipe and triggering the Print Spooler service (running as SYSTEM) to connect to it. Once connected, the SYSTEM token is captured and stored for impersonation.

This is the preferred method for escalating from service accounts (NETWORK SERVICE, LOCAL SERVICE, IIS AppPool, MSSQL) to SYSTEM when `SeImpersonatePrivilege` is available.

**Requires:**
- `SeImpersonatePrivilege` (standard on service accounts)
- Print Spooler service running (`sc query spooler`)

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| timeout | No | 15 | Seconds to wait for the Print Spooler to connect |

## Usage

### Basic usage (one command)
```
printspoofer
```
Creates a pipe at `\\.\pipe\{random}\pipe\spoolss`, triggers the Print Spooler via `OpenPrinterW`, captures the SYSTEM token.

### With custom timeout
```
printspoofer -timeout 30
```

## How It Works

1. Checks `SeImpersonatePrivilege` is available
2. Creates a named pipe: `\\.\pipe\{suffix}\pipe\spoolss`
3. Calls `OpenPrinterW("\\COMPUTERNAME/pipe/{suffix}")` via `winspool.drv`
4. The Print Spooler (SYSTEM) resolves this to `\\COMPUTERNAME\pipe\{suffix}\pipe\spoolss` and connects
5. `ImpersonateNamedPipeClient` captures the SYSTEM token
6. Token is duplicated and stored in the global identity system

## After Escalation

```
whoami          # Verify SYSTEM context
rev2self        # Revert to original identity when done
```

## Comparison with pipe-server

| Feature | printspoofer | pipe-server |
|---------|-------------|-------------|
| Steps | One command | Requires separate trigger (e.g., coerce) |
| Target | Local Print Spooler | Any connecting client |
| Use case | Quick SYSTEM escalation | General pipe impersonation |

Use `printspoofer` for straightforward SYSTEM escalation. Use `pipe-server` when you need to impersonate a specific remote client connecting to a custom pipe.

## MITRE ATT&CK Mapping

- **T1134.001** — Access Token Manipulation: Token Impersonation/Theft
