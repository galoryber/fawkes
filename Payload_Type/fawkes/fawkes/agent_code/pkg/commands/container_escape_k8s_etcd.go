//go:build linux

package commands

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// escapeK8sEtcd discovers in-cluster etcd endpoints by inspecting the
// kube-system control-plane pods (etcd and kube-apiserver static pods publish
// their listen/advertise URLs in their container args), augments the
// resulting list with the usual loopback + apiserver fallbacks, then issues
// an unauthenticated GET /version against each endpoint.
//
// Outcome per endpoint is one of:
//
//	unauth        — anonymous read succeeded (no client cert, no token)
//	auth-required — endpoint reachable but requires creds (HTTP 401/403)
//	tls-required  — endpoint requires mTLS / valid TLS handshake
//	unreachable   — dial/connect failed (firewall, downed service, wrong IP)
//	error         — anything else (parse failures, unexpected HTTP codes)
//
// Note on TLS: the probe uses InsecureSkipVerify so we can distinguish a
// server-cert-validation problem (we don't care) from a client-cert
// requirement (the actual etcd auth gate). The probe never sends any
// authentication material to the etcd endpoint; that is the test.
//
// args.Path is honoured as an explicit namespace override (defaults to
// "kube-system"). Useful for distros that run etcd outside the conventional
// namespace.
func escapeK8sEtcd(args containerEscapeArgs) (string, string) {
	kc, err := newK8sClient()
	if err != nil {
		return fmt.Sprintf("K8s etcd enumeration failed: %v", err), "error"
	}
	defer structs.ZeroString(&kc.token)

	ns := strings.TrimSpace(args.Path)
	if ns == "" {
		ns = "kube-system"
	}

	var sb strings.Builder
	sb.WriteString("=== KUBERNETES ETCD ENUMERATION ===\n\n")
	sb.WriteString(fmt.Sprintf("API Server:        %s\n", kc.apiServer))
	sb.WriteString(fmt.Sprintf("Inspected NS:      %s\n", ns))

	endpoints, podErr := discoverEtcdEndpoints(kc, ns)
	if podErr != "" {
		sb.WriteString(fmt.Sprintf("[!] pod inspection in %s: %s\n", ns, podErr))
	}
	endpoints = append(endpoints, defaultEtcdFallbacks(kc)...)
	endpoints = dedupeEndpoints(endpoints)

	sb.WriteString(fmt.Sprintf("Endpoints to probe: %d\n\n", len(endpoints)))
	if len(endpoints) == 0 {
		sb.WriteString("No etcd endpoints discovered. Pod inspection failed and fallbacks were empty.\n")
		return sb.String(), "success"
	}

	sb.WriteString("--- Discovered Endpoints ---\n")
	for _, e := range endpoints {
		sb.WriteString(fmt.Sprintf("  %-32s (source: %s)\n", e.URL, e.Source))
	}

	client := newEtcdProbeClient()
	var results []k8sEtcdProbeResult
	for _, e := range endpoints {
		results = append(results, probeEtcdEndpoint(client, e.URL))
	}

	unauthCount := 0
	sb.WriteString("\n--- Probe Results ---\n")
	sort.SliceStable(results, func(i, j int) bool {
		return etcdProbeRank(results[i].Status) < etcdProbeRank(results[j].Status)
	})
	for _, r := range results {
		if r.UnauthAccess {
			unauthCount++
		}
		sb.WriteString(fmt.Sprintf("  [%s] %s\n", strings.ToUpper(r.Status), r.URL))
		if r.Detail != "" {
			sb.WriteString(fmt.Sprintf("        %s\n", r.Detail))
		}
	}

	sb.WriteString(fmt.Sprintf("\n--- Summary ---\n  Unauthenticated reads: %d / %d endpoint(s)\n",
		unauthCount, len(results)))
	if unauthCount > 0 {
		sb.WriteString("  [!] Unauthenticated etcd access enables full cluster compromise — every secret, every config, every account token is readable. Suggested follow-up: etcdctl --endpoints=<url> get / --prefix --keys-only\n")
	}

	return sb.String(), "success"
}

// discoverEtcdEndpoints lists pods in the given namespace and extracts client
// URLs from any etcd / kube-apiserver container's command + args.
func discoverEtcdEndpoints(kc *k8sClient, ns string) ([]k8sEtcdEndpoint, string) {
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods", ns)
	data, code, err := kc.k8sGet(path)
	if err != nil {
		return nil, err.Error()
	}
	defer structs.ZeroBytes(data)
	if code != 200 {
		return nil, fmt.Sprintf("HTTP %d", code)
	}

	var resp struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Spec struct {
				Containers []struct {
					Name    string   `json:"name"`
					Command []string `json:"command"`
					Args    []string `json:"args"`
				} `json:"containers"`
			} `json:"spec"`
		} `json:"items"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err.Error()
	}

	var out []k8sEtcdEndpoint
	for _, pod := range resp.Items {
		for _, c := range pod.Spec.Containers {
			tokens := append(append([]string{}, c.Command...), c.Args...)
			urls := parseEtcdEndpointsFromArgs(tokens)
			if len(urls) == 0 {
				continue
			}
			source := fmt.Sprintf("kube-apiserver/%s/--etcd-servers", pod.Metadata.Name)
			if containerIsEtcd(c.Name, c.Command, c.Args) {
				source = fmt.Sprintf("etcd-pod/%s", pod.Metadata.Name)
			}
			for _, raw := range urls {
				if norm := normalizeEtcdURL(raw, "https"); norm != "" {
					out = append(out, k8sEtcdEndpoint{URL: norm, Source: source})
				}
			}
		}
	}
	return out, ""
}

// defaultEtcdFallbacks returns probe candidates that should be tried even
// when pod inspection turned up nothing — loopback (single-node clusters,
// kubeadm minikube) and the apiserver host on the etcd client port.
func defaultEtcdFallbacks(kc *k8sClient) []k8sEtcdEndpoint {
	out := []k8sEtcdEndpoint{
		{URL: "https://127.0.0.1:2379", Source: "default/loopback-https"},
		{URL: "http://127.0.0.1:2379", Source: "default/loopback-http"},
	}
	apiHost := apiServerHost(kc.apiServer)
	if apiHost != "" {
		out = append(out,
			k8sEtcdEndpoint{URL: fmt.Sprintf("https://%s:2379", apiHost), Source: "default/apiserver-host"},
		)
	}
	return out
}

// apiServerHost extracts the host portion of a "scheme://host:port" URL.
// Returns "" if extraction fails.
func apiServerHost(api string) string {
	s := api
	if idx := strings.Index(s, "://"); idx != -1 {
		s = s[idx+3:]
	}
	if slash := strings.IndexByte(s, '/'); slash != -1 {
		s = s[:slash]
	}
	// Strip port if present. Handle bracketed IPv6.
	if strings.HasPrefix(s, "[") {
		if end := strings.LastIndexByte(s, ']'); end != -1 {
			return s[:end+1]
		}
		return s
	}
	if colon := strings.LastIndexByte(s, ':'); colon != -1 {
		return s[:colon]
	}
	return s
}

// newEtcdProbeClient builds the HTTP client used for endpoint probing.
// InsecureSkipVerify is intentional: we WANT to see the server response
// even if the cert is self-signed; the real auth gate is whether the
// server demands a client cert (we never present one), and that surfaces
// as a TLS handshake error which we classify separately.
func newEtcdProbeClient() *http.Client {
	return &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, // #nosec G402
			ResponseHeaderTimeout: 4 * time.Second,
			DisableKeepAlives:     true,
		},
	}
}

// probeEtcdEndpoint issues GET /version against url. The returned result
// captures reachability, auth posture, and (on success) the reported etcd
// version. Never sends Authorization — that would defeat the test.
func probeEtcdEndpoint(client *http.Client, url string) k8sEtcdProbeResult {
	req, err := http.NewRequest("GET", url+"/version", nil)
	if err != nil {
		return k8sEtcdProbeResult{URL: url, Status: "error", Detail: err.Error()}
	}
	req.Header.Set("User-Agent", "kube-probe/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return classifyEtcdProbe(url, 0, nil, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return classifyEtcdProbe(url, resp.StatusCode, body, nil)
}

// etcdProbeRank orders probe statuses for human display: unauthenticated
// reads first (this is the operator's "show me what I got") then auth /
// tls / unreachable / error so the noisy negatives sink to the bottom.
func etcdProbeRank(s string) int {
	switch s {
	case "unauth":
		return 0
	case "auth-required":
		return 1
	case "tls-required":
		return 2
	case "unreachable":
		return 3
	}
	return 9
}
