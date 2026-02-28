+++
title = "runas"
chapter = false
weight = 197
hidden = false
+++

{{% notice info %}}Windows Only{{% /notice %}}

## Summary

Execute a command as a different user via `CreateProcessWithLogonW`. Unlike `make-token` (which applies thread-level impersonation), `runas` creates a fully new process under a new logon session with the specified credentials.

Supports `/netonly` mode where the process runs locally as the current user but uses the specified credentials for all network authentication — useful for accessing remote resources with different domain credentials.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| command | Yes | - | Command line to execute (e.g., `cmd.exe /c whoami`) |
| username | Yes | - | Target username (DOMAIN\user or user@domain) |
| password | Yes | - | Target user's password |
| domain | No | . | Domain (auto-parsed from username if DOMAIN\user format) |
| netonly | No | false | Network-only credentials (like `runas /netonly`) |

## Usage

Run a command as a different user:
```
runas -command "cmd.exe /c whoami" -username CORP\admin -password AdminPass1
```

Network-only mode (local identity unchanged, network identity switched):
```
runas -command "cmd.exe /c net use \\\\dc01\\c$" -username CORP\admin -password AdminPass1 -netonly true
```

## Comparison with make-token

| Feature | runas | make-token |
|---------|-------|------------|
| Scope | New process | Current thread |
| Logon session | New session created | Thread impersonation |
| Local identity | Target user | Original user |
| Network identity | Target user | Target user |
| Process output | Not captured (fire-and-forget) | N/A |
| Netonly mode | Yes | Yes (default) |

## MITRE ATT&CK Mapping

- **T1134.002** — Access Token Manipulation: Create Process with Token
