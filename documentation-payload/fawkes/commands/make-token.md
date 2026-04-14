+++
title = "make-token"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Create a token from plaintext credentials. Three actions are available:

- **impersonate** (default): Create the token and impersonate it on the current thread. The default logon type is 9 (`NEW_CREDENTIALS`), which only affects network identity (similar to `runas /netonly`).
- **spawn**: Create the token and launch a new process running under that token's security context via `CreateProcessWithTokenW`. The current thread is not affected.
- **auto-verify**: Create and impersonate the token, then automatically chain `whoami` and `getprivs` to verify the new identity and privileges.

### Arguments

#### action (optional)
- `impersonate` (default): Create token and impersonate.
- `spawn`: Create token and spawn a process with it.
- `auto-verify`: Impersonate then auto-run whoami + getprivs verification chain.

#### username
Username to create the token for.

#### domain (optional)
Domain for the user. Use `.` for local accounts. Default: `.`

#### password
Password for the user.

#### logon_type (optional)
Windows logon type. Default: `9` (NewCredentials).

Common values:
- `2` - Interactive (changes local and network identity)
- `3` - Network
- `9` - NewCredentials (network identity only, like `runas /netonly`)

For spawn, type 2 (Interactive) creates a full logon session for the spawned process.

#### command (required for spawn)
Command line to execute when action=spawn.

## Usage
```
make-token -username <user> -domain <domain> -password <pass> [-logon_type <type>]
make-token -username <user> -domain <domain> -password <pass> -action spawn -command <cmd>
make-token -username <user> -domain <domain> -password <pass> -action auto-verify
```

Examples
```
# Impersonate (default)
make-token -username admin -domain CORP -password P@ssw0rd!
make-token -username localadmin -domain . -password Password1 -logon_type 2

# Auto-verify: impersonate then confirm identity + privileges
make-token -username admin -domain CORP -password P@ssw0rd! -action auto-verify

# Spawn a process as the target user
make-token -username admin -domain CORP -password P@ssw0rd! -action spawn -command "cmd.exe /c dir \\\\fileserver\\share"
```

## Notes

- **Credential Vault**: Credentials used for token creation are automatically reported to Mythic's Credentials store as plaintext credentials (both impersonate and spawn).
- **Token Tracking**: When using impersonate, the created token is registered with Mythic's Callback Tokens tracker.
- **Spawn vs Impersonate**: Use `spawn` when you need a new process running as the target user (e.g., deploying a payload) without changing your current callback's identity. Use `impersonate` when you want all subsequent commands to run as the target user.
- **Spawn Cleanup**: Kill the spawned process to clean up. The token is not stored on the current thread.
- Use `rev2self` to drop impersonation and revert to the original security context (impersonate action only).

## MITRE ATT&CK Mapping

- T1134.001 — Token Impersonation/Theft
- T1134.002 — Create Process with Token (spawn action)
