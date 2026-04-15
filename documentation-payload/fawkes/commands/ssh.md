+++
title = "ssh"
chapter = false
weight = 114
hidden = false
+++

## Summary

Execute commands, push files, or create SSH tunnels to remote hosts. Cross-platform lateral movement, tool transfer, and pivoting.

Actions:
- **exec** (default): Execute a command on the remote host and return output.
- **push**: Transfer a local file from the agent to the remote host via SSH session (lateral tool transfer T1570).
- **tunnel-local**: Local port forwarding (`ssh -L`). Agent listens locally, forwards through SSH to remote target.
- **tunnel-remote**: Remote port forwarding (`ssh -R`). SSH host listens, forwards back through SSH to agent-accessible target.
- **tunnel-dynamic**: Dynamic SOCKS5 proxy (`ssh -D`). Agent listens as SOCKS proxy, routes all traffic through SSH.
- **tunnel-list**: List active SSH tunnels.
- **tunnel-stop**: Stop a specific SSH tunnel by ID.

Supports three authentication methods:
- **Password authentication** (including keyboard-interactive fallback)
- **Key file** -- read SSH private key from agent's filesystem
- **Inline key data** -- pass PEM-encoded private key directly

## Arguments

| Argument | Required | Type | Default | Description |
|----------|----------|------|---------|-------------|
| action | No | choose_one | exec | Action to perform (see above) |
| host | Yes | string | | Target SSH host IP or hostname |
| username | Yes | string | | SSH username |
| command | Conditional | string | | Command to execute (required for exec action) |
| password | No | string | | Password for SSH auth (also used as key passphrase) |
| key_path | No | string | | Path to SSH private key on agent filesystem |
| key_data | No | string | | Inline SSH private key in PEM format |
| source | Conditional | string | | Local file path on agent (required for push action) |
| destination | Conditional | string | | Remote file path to write to (required for push action) |
| port | No | number | 22 | SSH port |
| timeout | No | number | 60 | Connection and command timeout in seconds |
| local_port | Conditional | number | | Local port (tunnel-local/dynamic: listen port; tunnel-remote: forward target port) |
| remote_host | Conditional | string | | Target host for local tunnel forwarding |
| remote_port | Conditional | number | | Remote port (tunnel-local: target port; tunnel-remote: listen port) |
| bind_address | No | string | 127.0.0.1 | Bind address for tunnel listeners |
| tunnel_id | Conditional | string | | Tunnel ID for tunnel-stop action |

At least one authentication method must be provided (`password`, `key_path`, or `key_data`).

## Usage

### Execute Commands (exec action)

```
ssh -host 192.168.1.100 -username root -password toor -command "whoami"
ssh -host 192.168.1.100 -username setup -key_path /home/user/.ssh/id_rsa -command "hostname && id"
```

### Push Files (push action)

```
ssh -action push -host 192.168.1.100 -username root -password toor -source /tmp/payload -destination /tmp/payload
```

### Local Port Forward (tunnel-local)

Forward local port 8080 through SSH host to internal web server:
```
ssh -action tunnel-local -host 10.0.0.1 -username admin -password pass -local_port 8080 -remote_host 172.16.0.5 -remote_port 80
```
Traffic to `agent:8080` is forwarded through `10.0.0.1` to `172.16.0.5:80`.

### Remote Port Forward (tunnel-remote)

Make agent's RDP port accessible from the SSH host:
```
ssh -action tunnel-remote -host 10.0.0.1 -username admin -password pass -remote_port 9090 -local_port 3389
```
Traffic to `10.0.0.1:9090` is forwarded back to `agent:3389`.

### Dynamic SOCKS Proxy (tunnel-dynamic)

Create a SOCKS5 proxy through the SSH host:
```
ssh -action tunnel-dynamic -host 10.0.0.1 -username admin -password pass -local_port 1080
```
Configure tools to use `agent:1080` as a SOCKS5 proxy. All traffic routes through `10.0.0.1`.

### Manage Tunnels

```
ssh -action tunnel-list
ssh -action tunnel-stop -tunnel_id ssh-local-10.0.0.1-8080
```

## Notes

- Tunnels run as background jobs until stopped via `tunnel-stop`
- Each tunnel maintains the SSH connection for its lifetime
- Idle connections timeout after 5 minutes to prevent zombie goroutines
- SOCKS5 proxy supports CONNECT method (IPv4, IPv6, domain names)
- Uses pure Go `golang.org/x/crypto/ssh` library -- no external SSH binary needed
- Works cross-platform: can create tunnels from Windows, Linux, or macOS agents

## MITRE ATT&CK Mapping

- **T1021.004** -- Remote Services: SSH
- **T1570** -- Lateral Tool Transfer (push action)
- **T1572** -- Protocol Tunneling (tunnel actions)
