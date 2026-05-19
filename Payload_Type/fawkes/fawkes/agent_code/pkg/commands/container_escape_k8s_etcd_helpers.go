package commands

// etcd discovery and probe helpers for K8s container escape.
// Used by container_escape_k8s_etcd.go.

import (
	"encoding/json"
	"fmt"
	"strings"
)

// k8sEtcdEndpoint records one discovered etcd client URL plus the in-cluster
// source it was discovered from.
type k8sEtcdEndpoint struct {
	URL    string
	Source string
}

// k8sEtcdProbeResult captures the outcome of one etcd reachability probe.
type k8sEtcdProbeResult struct {
	URL          string
	Status       string
	Detail       string
	EtcdServer   string
	EtcdCluster  string
	HTTPStatus   int
	UnauthAccess bool
}

// containerIsEtcd returns true when a pod-container name+args pair looks like
// an etcd server.
func containerIsEtcd(name string, command []string, args []string) bool {
	if strings.EqualFold(name, "etcd") {
		return true
	}
	all := append([]string{}, command...)
	all = append(all, args...)
	for _, a := range all {
		la := strings.ToLower(a)
		if strings.Contains(la, "--listen-client-urls") ||
			strings.Contains(la, "--advertise-client-urls") {
			return true
		}
	}
	return false
}

// parseEtcdEndpointsFromArgs scans a command/args slice and returns every
// URL extracted from etcd-related flags.
func parseEtcdEndpointsFromArgs(tokens []string) []string {
	wanted := map[string]bool{
		"--etcd-servers":          true,
		"--listen-client-urls":    true,
		"--advertise-client-urls": true,
	}
	var out []string
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		lower := strings.ToLower(t)
		if eq := strings.IndexByte(t, '='); eq != -1 {
			if wanted[strings.ToLower(t[:eq])] {
				out = append(out, splitCSV(t[eq+1:])...)
				continue
			}
		}
		if wanted[lower] && i+1 < len(tokens) {
			out = append(out, splitCSV(tokens[i+1])...)
			i++
		}
	}
	return out
}

// splitCSV splits a comma-separated string and trims whitespace.
func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// normalizeEtcdURL canonicalises a discovered URL into "scheme://host:port" form.
func normalizeEtcdURL(raw, defaultScheme string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	scheme := defaultScheme
	if scheme == "" {
		scheme = "https"
	}
	if idx := strings.Index(s, "://"); idx != -1 {
		scheme = strings.ToLower(s[:idx])
		s = s[idx+3:]
	}
	if slash := strings.IndexByte(s, '/'); slash != -1 {
		s = s[:slash]
	}
	if s == "" {
		return ""
	}
	if !strings.ContainsRune(s, ':') || isBracketedIPv6WithoutPort(s) {
		s += ":2379"
	}
	return scheme + "://" + s
}

// isBracketedIPv6WithoutPort returns true when s is "[…]" with no trailing ":port".
func isBracketedIPv6WithoutPort(s string) bool {
	if !strings.HasPrefix(s, "[") {
		return false
	}
	end := strings.LastIndexByte(s, ']')
	return end == len(s)-1
}

// dedupeEndpoints removes URL duplicates while preserving order.
func dedupeEndpoints(in []k8sEtcdEndpoint) []k8sEtcdEndpoint {
	seen := make(map[string]bool, len(in))
	var out []k8sEtcdEndpoint
	for _, e := range in {
		if e.URL == "" || seen[e.URL] {
			continue
		}
		seen[e.URL] = true
		out = append(out, e)
	}
	return out
}

// classifyEtcdProbe converts the raw HTTP outcome of an etcd probe into a
// structured result.
func classifyEtcdProbe(url string, httpStatus int, body []byte, httpErr error) k8sEtcdProbeResult {
	r := k8sEtcdProbeResult{URL: url, HTTPStatus: httpStatus}
	if httpErr != nil {
		msg := httpErr.Error()
		lower := strings.ToLower(msg)
		switch {
		case strings.Contains(lower, "tls"),
			strings.Contains(lower, "x509"),
			strings.Contains(lower, "certificate"),
			strings.Contains(lower, "handshake"):
			r.Status = "tls-required"
			r.Detail = msg
		case strings.Contains(lower, "connection refused"),
			strings.Contains(lower, "no route to host"),
			strings.Contains(lower, "i/o timeout"),
			strings.Contains(lower, "timeout"),
			strings.Contains(lower, "deadline exceeded"):
			r.Status = "unreachable"
			r.Detail = msg
		default:
			r.Status = "error"
			r.Detail = msg
		}
		return r
	}
	switch {
	case httpStatus == 200:
		if v, err := parseEtcdVersionResponse(body); err == nil && v.Server != "" {
			r.Status = "unauth"
			r.EtcdServer = v.Server
			r.EtcdCluster = v.Cluster
			r.UnauthAccess = true
			r.Detail = fmt.Sprintf("etcdserver=%s cluster=%s", v.Server, v.Cluster)
			return r
		}
		r.Status = "unauth"
		r.UnauthAccess = true
		r.Detail = truncateBody(body, 80)
	case httpStatus == 401 || httpStatus == 403:
		r.Status = "auth-required"
		r.Detail = fmt.Sprintf("HTTP %d", httpStatus)
	case httpStatus == 400:
		bodyLower := strings.ToLower(string(body))
		if strings.Contains(bodyLower, "client certificate") || strings.Contains(bodyLower, "client cert") || strings.Contains(bodyLower, "tls handshake") {
			r.Status = "tls-required"
			r.Detail = "HTTP 400 client-cert required"
		} else {
			r.Status = "error"
			r.Detail = "HTTP 400"
		}
	default:
		r.Status = "error"
		r.Detail = fmt.Sprintf("HTTP %d", httpStatus)
	}
	return r
}

// k8sEtcdVersion is the JSON shape returned by GET /version on etcd v3.
type k8sEtcdVersion struct {
	Server  string `json:"etcdserver"`
	Cluster string `json:"etcdcluster"`
}

// parseEtcdVersionResponse decodes a /version response body.
func parseEtcdVersionResponse(body []byte) (k8sEtcdVersion, error) {
	var v k8sEtcdVersion
	if len(body) == 0 {
		return v, fmt.Errorf("empty body")
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return v, err
	}
	if v.Server == "" {
		return v, fmt.Errorf("missing etcdserver field")
	}
	return v, nil
}

// truncateBody returns at most n bytes of body as a single-line string.
func truncateBody(body []byte, n int) string {
	s := strings.TrimSpace(string(body))
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
