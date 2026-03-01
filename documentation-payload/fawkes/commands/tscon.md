+++
title = "tscon"
chapter = false
weight = 198
hidden = false
+++

{{% notice info %}}Windows Only{{% /notice %}}

## Summary

RDP session management via Windows Terminal Services API. Lists active/disconnected RDP sessions, hijacks disconnected sessions (requires SYSTEM), and disconnects users.

Session hijacking allows an operator running as SYSTEM to take over another user's disconnected RDP session without knowing their password. This is particularly useful after obtaining SYSTEM via `getsystem` or `pipe-server`.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | list | Action: list, hijack, disconnect |
| session_id | No | - | Target session ID (required for hijack/disconnect) |

## Usage

List all RDP sessions:
```
tscon
```

Hijack a disconnected session (requires SYSTEM):
```
tscon -action hijack -session_id 2
```

Disconnect a user's session:
```
tscon -action disconnect -session_id 3
```

## Sample Output

```
=== RDP SESSIONS ===

ID     Station              State           Username             Domain
--------------------------------------------------------------------------------
0      Services             Active
1      Console              Active          admin                WIN11-PC
2      RDP-Tcp#1            Disconnected    jsmith               CORP

Current session: 0
```

## Notes

- **Hijacking requires SYSTEM privileges** — use `getsystem` first
- Only disconnected sessions can be hijacked without a password
- Active sessions require the target user's password (not supported)
- The hijacked session's desktop becomes accessible to the operator

## MITRE ATT&CK Mapping

- **T1563.002** — Remote Service Session Hijacking: RDP Hijacking
