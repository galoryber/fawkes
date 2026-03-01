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

Steal and impersonate a security token from another process. Changes both local and network identity. Requires administrator privileges or SeDebugPrivilege to steal tokens from other users' processes.

### Arguments

#### pid
Process ID to steal the token from (e.g., a process running as a different user).

## Usage
```
steal-token <PID>
```

Example
```
steal-token 672
```

## Notes

- **Token Tracking**: The stolen token is registered with Mythic's Callback Tokens tracker, showing the impersonated identity and source PID.
- Use `rev2self` to drop impersonation and revert to the original security context.
- Use `enum-tokens` to list available tokens before stealing.

## MITRE ATT&CK Mapping

- T1134.001
