+++
title = "ssh"
chapter = false
weight = 114
hidden = false
+++

## Summary

Execute commands on remote hosts via SSH with password or key-based authentication. Cross-platform lateral movement command that works from Windows, Linux, and macOS agents.

Supports three authentication methods:
- **Password authentication** (including keyboard-interactive fallback)
- **Key file** — read SSH private key from agent's filesystem
- **Inline key data** — pass PEM-encoded private key directly

## Arguments

| Argument | Required | Type | Default | Description |
|----------|----------|------|---------|-------------|
| host | Yes | string | | Target host IP or hostname |
| username | Yes | string | | SSH username |
| command | Yes | string | | Command to execute on the remote host |
| password | No | string | | Password for SSH auth (also used as key passphrase) |
| key_path | No | string | | Path to SSH private key on agent filesystem |
| key_data | No | string | | Inline SSH private key in PEM format |
| port | No | number | 22 | SSH port |
| timeout | No | number | 60 | Connection and command timeout in seconds |

At least one authentication method must be provided (`password`, `key_path`, or `key_data`).

## Usage

**Password authentication:**
```
ssh -host 192.168.1.100 -username root -password toor -command "whoami"
```

**Key file authentication:**
```
ssh -host 192.168.1.100 -username setup -key_path /home/user/.ssh/id_rsa -command "hostname && id"
```

**Key file with passphrase:**
```
ssh -host 192.168.1.100 -username admin -key_path /root/.ssh/id_ed25519 -password keypass -command "cat /etc/shadow"
```

**Inline key data:**
```
ssh -host 192.168.1.100 -username root -key_data "-----BEGIN OPENSSH PRIVATE KEY-----\n..." -command "uname -a"
```

**Custom port and timeout:**
```
ssh -host 10.0.0.5 -username deploy -key_path /tmp/key -command "docker ps" -port 2222 -timeout 30
```

## Notes

- Authentication methods are tried in order: key auth first (if provided), then password, then keyboard-interactive
- Password authentication includes keyboard-interactive fallback for servers that use PAM-based auth
- Host key verification is disabled (standard for red team tooling)
- Combined stdout and stderr output is returned
- Non-zero exit codes are reported but still return "success" status (command executed, just returned non-zero)
- Connection errors (unreachable host, auth failure) return "error" status
- Uses pure Go `golang.org/x/crypto/ssh` library — no external SSH binary needed
- Works cross-platform: can SSH from Windows, Linux, or macOS agents

## MITRE ATT&CK Mapping

- **T1021.004** — Remote Services: SSH
