+++
title = "pkg-list"
chapter = false
weight = 213
hidden = false
+++

## Summary

List installed packages and software. Enumerates system packages and applications using the platform's native package management tools. Useful for identifying installed software, potential attack surface, and privilege escalation opportunities.

## Arguments

No arguments required.

## Usage

```
pkg-list
```

## Platform Details

### Linux
- **dpkg** (Debian/Ubuntu): Queries installed packages with versions
- **rpm** (RHEL/CentOS/Fedora): Queries installed RPMs with versions
- **apk** (Alpine): Lists installed packages
- **snap**: Enumerates snap packages if available
- **flatpak**: Enumerates flatpak apps if available
- Output limited to first 100 packages per manager to avoid excessive output

### macOS
- **Homebrew**: Lists installed formulae and casks with versions
- **Applications**: Enumerates `.app` bundles in `/Applications`
- Output limited to first 100 entries per source

### Windows
- Queries registry Uninstall keys (both 32-bit and 64-bit) via PowerShell
- Reports program name and version
- Output limited to first 200 entries

## OPSEC Considerations

- Linux/macOS: Executes `dpkg-query`, `rpm`, `apk`, `brew`, `snap`, `flatpak` commands
- Windows: Spawns `powershell.exe` to read registry — may be logged by command-line auditing
- Consider using this early in an engagement before increased monitoring

## MITRE ATT&CK Mapping

- **T1518** — Software Discovery
