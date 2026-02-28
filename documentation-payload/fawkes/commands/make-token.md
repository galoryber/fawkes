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

Create a token from credentials and impersonate it. The default logon type is 9 (`NEW_CREDENTIALS`), which only affects network identity (similar to `runas /netonly`) - `whoami` will still show the original user. Use logon type 2 (`INTERACTIVE`) to change both local and network identity.

### Arguments

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

## Usage
```
make-token -username <user> -domain <domain> -password <pass> [-logon_type <type>]
```

Example
```
make-token -username admin -domain CORP -password P@ssw0rd!
make-token -username localadmin -domain . -password Password1 -logon_type 2
```

## Notes

- **Credential Vault**: Credentials used for token creation are automatically reported to Mythic's Credentials store as plaintext credentials.
- **Token Tracking**: The created token is registered with Mythic's Callback Tokens tracker, providing visibility into which tokens are associated with each callback.
- Use `rev2self` to drop impersonation and revert to the original security context.

## MITRE ATT&CK Mapping

- T1134.001
