+++
title = "rev2self"
chapter = false
weight = 103
hidden = false
+++

{{% notice info %}}
Windows Only
{{% /notice %}}

## Summary

Revert to the original security context by dropping any active impersonation token created by `make-token` or `steal-token`.

### Arguments

No arguments.

## Usage
```
rev2self
```

## Notes

- **Token Cleanup**: When rev2self successfully reverts impersonation, all tracked tokens are automatically removed from Mythic's Callback Tokens tracker.
- Shows identity before and after reversion (e.g., "Was: CORP\admin → Reverted to: NT AUTHORITY\SYSTEM").

## MITRE ATT&CK Mapping

- T1134.001
