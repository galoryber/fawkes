+++
title = "ide-recon"
chapter = false
weight = 218
hidden = false
+++

## Summary

Enumerate IDE (Integrated Development Environment) configurations to gather intelligence about developer workstations. Scans VS Code and JetBrains IDEs for extensions, remote SSH targets, recent projects, database connections, deployment servers, and secrets stored in settings.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | Yes | all | `vscode`: scan VS Code. `jetbrains`: scan JetBrains IDEs. `all`: scan both. |
| user | No | (current user) | Target a specific user's home directory |

## Usage

Scan all IDEs for the current user:
```
ide-recon -action all
```

Scan only VS Code:
```
ide-recon -action vscode
```

Scan JetBrains IDEs for a specific user:
```
ide-recon -action jetbrains -user admin
```

## What It Finds

### VS Code
- **Extensions**: Installed extensions categorized as Security/DevOps, Remote/SSH/Container, and Other
- **Settings**: Proxy configurations, SSH remote platform mappings, Docker hosts, cloud profiles
- **Sensitive Settings**: Any setting containing "password", "token", "secret", "credential", or "apikey"
- **Remote SSH Targets**: Hosts configured in VS Code Remote-SSH with their platform (linux/windows/macOS)
- **Recent Projects**: Recently opened workspaces and files (reveals what the developer works on)
- **Custom Keybindings**: Indicates custom tooling or workflows

### JetBrains (IntelliJ IDEA, PyCharm, GoLand, WebStorm, etc.)
- **Installed Products**: Discovers which JetBrains IDEs are installed with versions
- **Recent Projects**: Recently opened project paths
- **Data Sources**: Database connection strings (JDBC URLs), usernames, server addresses
- **Deployment Servers**: Configured remote servers for deployment (SSH/SFTP targets)

## Intelligence Value

- **Lateral Movement**: Remote SSH hosts and deployment servers reveal internal infrastructure targets
- **Credential Access**: Database connection strings may contain credentials; settings may store API tokens
- **Situational Awareness**: Recent projects and extensions reveal the tech stack and what the user works on
- **Privilege Escalation**: Database connections may lead to privileged data stores

## MITRE ATT&CK Mapping

- **T1005** — Data from Local System
- **T1083** — File and Directory Discovery

## Platform Support

Cross-platform: Windows, Linux, macOS. Config paths are platform-aware:
- **Linux**: `~/.config/Code/`, `~/.config/JetBrains/`
- **macOS**: `~/Library/Application Support/Code/`, `~/Library/Application Support/JetBrains/`
- **Windows**: `%APPDATA%\Code\`, `%APPDATA%\JetBrains\`
