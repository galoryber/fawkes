+++
title = "token-store"
chapter = false
weight = 221
hidden = false
+++

## Summary

Manage a named token vault for quick identity switching. Save stolen or created tokens, list all saved entries, switch between them, or remove entries. Enables operators to maintain multiple identities simultaneously without re-stealing tokens.

{{% notice info %}}Windows Only{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `-action` | Yes | `list` | Action: `save`, `list`, `use`, `remove` |
| `-name` | For save/use/remove | | Label for the token |

## Usage

### Save current token
After `steal-token` or `make-token`, save the active token with a label:
```
steal-token 1234
token-store -action save -name "admin"
```

### List stored tokens
```
token-store -action list
```
Output shows name, identity (DOMAIN\user), source (steal-token/make-token), and whether credentials are attached.

### Switch to a stored token
```
token-store -action use -name "admin"
```
Replaces the current impersonation with the stored token. The stored copy remains in the vault.

### Remove a stored token
```
token-store -action remove -name "admin"
```

### Typical workflow
```
# Steal SYSTEM token and save it
steal-token 4          # winlogon.exe → SYSTEM
token-store -action save -name "system"

# Create domain admin token and save it
make-token -domain CORP -username dadmin -password P@ss
token-store -action save -name "da"

# Switch between identities as needed
token-store -action use -name "system"   # → SYSTEM
token-store -action use -name "da"       # → CORP\dadmin
rev2self                                  # → original process token
token-store -action use -name "system"   # → back to SYSTEM
```

## Notes

- Tokens are stored as duplicated handles — independent of the active impersonation
- Credentials from `make-token` are preserved and restored when using that token
- The token store lives in memory only — cleared on agent exit
- Use `rev2self` to drop impersonation without affecting the store
- Stored tokens remain valid until the source process exits or the token is revoked

## MITRE ATT&CK Mapping

- **T1134.001** — Access Token Manipulation: Token Impersonation/Theft
