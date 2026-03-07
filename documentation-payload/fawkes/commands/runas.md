+++
title = "runas"
chapter = false
weight = 197
hidden = false
+++

## Summary

Execute a command as a different user. Cross-platform support with platform-specific mechanisms.

### Platform Support

| Mechanism | Windows | macOS | Linux |
|-----------|---------|-------|-------|
| CreateProcessWithLogonW | Yes | No | No |
| setuid/setgid (root) | No | Yes | Yes |
| sudo -S (with password) | No | Yes | Yes |
| /netonly mode | Yes | No | No |

### Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| command | Yes | - | Command to execute (e.g., `cmd.exe /c whoami` on Windows, `id` on Unix) |
| username | Yes | - | Target username (DOMAIN\user or user@domain on Windows; local username on Unix) |
| password | Windows: Yes; Unix: depends | - | Target user's password. On Unix: required if not root (uses sudo -S); optional if root (uses setuid). |
| domain | No | . | Domain (Windows only; auto-parsed from username if DOMAIN\user format) |
| netonly | No | false | Network-only credentials (Windows only — like `runas /netonly`) |

## Usage

### Windows — Run as different user

```
runas -command "cmd.exe /c whoami" -username CORP\admin -password AdminPass1
```

### Windows — Network-only mode

Local identity unchanged, network identity switched:
```
runas -command "cmd.exe /c net use \\\\dc01\\c$" -username CORP\admin -password AdminPass1 -netonly true
```

### Linux/macOS — As root (setuid)

When the agent is running as root, no password is needed:
```
runas -command "id" -username nobody
```

### Linux/macOS — With sudo

When not root, provide a password for sudo:
```
runas -command "cat /etc/shadow" -username root -password UserPass1
```

### Example Output (Linux, root)

```
[runas nobody (uid=65534, setuid)] uid=65534(nobody) gid=65534(nogroup)
```

### Example Output (Windows)

```
[+] Process created as CORP\admin (PID: 4328, mode: interactive)
Command: cmd.exe /c whoami
```

## How It Works

### Windows
1. Parses domain from username (supports `DOMAIN\user` and `user@domain` formats)
2. Calls `CreateProcessWithLogonW` with the specified credentials
3. Creates a hidden window (`SW_HIDE`) with `CREATE_NO_WINDOW` flag
4. Returns the spawned process PID (fire-and-forget — output is not captured)

### Linux/macOS (as root)
1. Looks up the target user via `os/user.Lookup` to get UID/GID
2. Spawns `/bin/sh -c <command>` with `SysProcAttr.Credential{Uid, Gid}`
3. Child process runs in a new session (`Setsid: true`)
4. Captures and returns combined stdout/stderr output

### Linux/macOS (with sudo)
1. Runs `sudo -S -u <username> -- /bin/sh -c <command>`
2. Pipes the password to stdin via `-S` flag
3. Strips sudo password prompts from output
4. Returns command output

## Comparison with make-token

| Feature | runas | make-token |
|---------|-------|------------|
| Scope | New process | Current thread |
| Logon session | New session created | Thread impersonation |
| Local identity | Target user | Original user |
| Network identity | Target user | Target user |
| Process output | Windows: not captured; Unix: captured | N/A |
| Netonly mode | Yes (Windows only) | Yes (default) |
| Platform | Windows, Linux, macOS | Windows only |

## Notes

- **Windows:** Process is spawned fire-and-forget; output is not captured. Use in combination with other commands for post-execution.
- **Linux/macOS as root:** Uses kernel-level `setuid`/`setgid` — most reliable and stealthy method.
- **Linux/macOS with sudo:** Requires `sudo` to be installed. The password is sent via stdin (`-S` flag). Sudo password prompts are stripped from output.
- **Domain handling on Unix:** Domain prefixes (`DOMAIN\user` or `user@domain`) are stripped — only the local username is used for user lookup.
- **netonly flag:** Only meaningful on Windows. Returns an error on Unix.

## MITRE ATT&CK Mapping

- **T1134.002** — Access Token Manipulation: Create Process with Token
