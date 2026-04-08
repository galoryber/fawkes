+++
title = "steal-token"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Steal a security token from another process. Two actions are available:

- **impersonate** (default): Steal the token and impersonate it on the current thread. Changes both local and network identity.
- **spawn**: Steal the token and create a new process running under that token's security context via `CreateProcessWithTokenW`. The current thread is not affected.

Requires administrator privileges or SeDebugPrivilege to steal tokens from other users' processes.

### Arguments

#### action (optional)
- `impersonate` (default): Steal and impersonate the token.
- `spawn`: Steal the token and spawn a process with it.

#### pid
Process ID to steal the token from (e.g., a process running as a different user).

#### command (required for spawn)
Command line to execute when action=spawn. Can be any executable path or command (e.g., `cmd.exe /c whoami`, or a payload path).

## Usage
```
steal-token -pid <PID>
steal-token -pid <PID> -action spawn -command <cmd>
```

Examples
```
# Impersonate (default)
steal-token -pid 672

# Spawn a process as the target user
steal-token -pid 672 -action spawn -command "cmd.exe /c whoami > C:\temp\out.txt"

# Spawn a Fawkes payload as SYSTEM (steal from winlogon)
steal-token -pid 612 -action spawn -command "C:\temp\payload.exe"
```

## Notes

- **Token Tracking**: When using impersonate, the stolen token is registered with Mythic's Callback Tokens tracker, showing the impersonated identity and source PID.
- **Spawn vs Impersonate**: Use `spawn` when you need a new process running as the target user without changing your current callback's identity. Use `impersonate` when you want all subsequent commands to run as the target user.
- **Spawn Cleanup**: Kill the spawned process to clean up. The token is not stored on the current thread.
- Use `rev2self` to drop impersonation and revert to the original security context (impersonate action only).
- Use `enum-tokens` to list available tokens before stealing.

## MITRE ATT&CK Mapping

- T1134.001 — Token Impersonation/Theft
- T1134.002 — Create Process with Token (spawn action)
