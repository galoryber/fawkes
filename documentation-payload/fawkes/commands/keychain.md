+++
title = "keychain"
chapter = false
weight = 34
hidden = false
+++

{{% notice info %}}
macOS Only
{{% /notice %}}

## Summary

Access macOS Keychain items using the `security` CLI. Enumerate keychains, dump metadata, search for generic passwords, internet passwords, and certificates.

When password data cannot be retrieved (keychain locked or authorization required), the command falls back to returning metadata without the password value.

### Arguments

| Parameter | Required | Description |
|-----------|----------|-------------|
| action | Yes | `list`, `dump`, `find-password`, `find-internet`, or `find-cert` |
| service | No | Service name filter (find-password). Example: `Wi-Fi`, `Chrome Safe Storage` |
| server | No | Server hostname filter (find-internet). Example: `github.com` |
| account | No | Account name filter (find-password, find-internet) |
| label | No | Label filter (find-password, find-internet) |
| name | No | Certificate common name filter (find-cert). Leave empty to list all. |

## Usage

```
# List all keychains
keychain -action list

# Dump all keychain metadata
keychain -action dump

# Search for a generic password by service name
keychain -action find-password -service "Wi-Fi"

# Search for an internet password by server
keychain -action find-internet -server "github.com"

# List all certificates
keychain -action find-cert

# Search for a specific certificate
keychain -action find-cert -name "Apple"
```

## MITRE ATT&CK Mapping

- T1555.001 — Credentials from Password Stores: Keychain
