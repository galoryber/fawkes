+++
title = "ls"
chapter = false
weight = 103
hidden = false
+++

## Summary

List files and folders in a directory with file ownership, group, permissions, and platform-specific timestamps. Defaults to the current working directory. Integrates with the Mythic file browser.

### File Ownership

File ownership is resolved per-platform:

- **Windows**: Uses `GetNamedSecurityInfo` + `LookupAccountSid` to resolve owner and group SIDs to `DOMAIN\Account` format (e.g., `NT SERVICE\TrustedInstaller`, `BUILTIN\Administrators`)
- **Linux**: Uses `syscall.Stat_t` UID/GID with `user.LookupId`/`LookupGroupId` for username/group name resolution
- **macOS**: Same as Linux (POSIX ownership model)

### Timestamps

- **Windows**: Access time (`LastAccessTime`), creation time (`CreationTime`), modify time (`LastWriteTime`)
- **Linux**: Access time (`Atim`), status change time (`Ctim`), modify time (`ModTime`)
- **macOS**: Access time (`Atimespec`), status change time (`Ctimespec`), modify time (`ModTime`)

### Arguments

#### path (optional)
Directory or file path to list. Defaults to current working directory.

## Usage
```
ls [path]
```

Example
```
ls
ls C:\Users\admin\Desktop
ls /var/log
```

## MITRE ATT&CK Mapping

- T1083
