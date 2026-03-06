+++
title = "password-managers"
chapter = false
weight = 143
hidden = false
+++

## Summary

Discovers password manager databases and configuration files on the target system. Checks for KeePass (.kdbx files), 1Password, Bitwarden, LastPass, Dashlane, and KeePassXC by searching known installation and data paths.

Cross-platform: Windows, Linux, macOS.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| depth | No | 4 | Maximum directory depth for .kdbx file search |

## Usage

Discover all password managers with default depth:
```
password-managers
```

Limit .kdbx search depth:
```
password-managers -depth 2
```

### What It Checks

| Manager | Detection Method |
|---------|-----------------|
| KeePass | Recursive .kdbx file search from home/user directories |
| 1Password | Known data directory paths per OS |
| Bitwarden | Known data directory paths per OS |
| LastPass | Browser extension data directories |
| Dashlane | Known data directory paths per OS |
| KeePassXC | Known config/data directory paths per OS |

## MITRE ATT&CK Mapping

- **T1555** — Credentials from Password Stores
- **T1555.005** — Credentials from Password Stores: Password Managers
