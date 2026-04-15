//go:build linux

package commands

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

const (
	k8sCAPath        = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	k8sNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// k8sTokenPath is defined in container_escape_helpers.go

// k8sClient holds authenticated HTTP client and API server info for K8s operations.
type k8sClient struct {
	client    *http.Client
	apiServer string
	token     string
	namespace string
}

// newK8sClient creates an authenticated K8s API client from service account credentials.
func newK8sClient() (*k8sClient, error) {
	// Read service account token
	tokenData, err := os.ReadFile(k8sTokenPath)
	if err != nil {
		return nil, fmt.Errorf("K8s service account token not found: %w", err)
	}
	token := strings.TrimSpace(string(tokenData))
	structs.ZeroBytes(tokenData)

	// Read namespace
	nsData, err := os.ReadFile(k8sNamespacePath)
	if err != nil {
		return nil, fmt.Errorf("K8s namespace not found: %w", err)
	}
	namespace := strings.TrimSpace(string(nsData))
	structs.ZeroBytes(nsData)

	// Discover API server from env
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("KUBERNETES_SERVICE_HOST/PORT not set — not running in K8s")
	}
	apiServer := fmt.Sprintf("https://%s:%s", host, port)

	// Build TLS config with CA cert if available
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caData, err := os.ReadFile(k8sCAPath); err == nil {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caData)
		tlsConfig.RootCAs = pool
		structs.ZeroBytes(caData)
	} else {
		tlsConfig.InsecureSkipVerify = true
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   30 * time.Second,
	}

	return &k8sClient{
		client:    client,
		apiServer: apiServer,
		token:     token,
		namespace: namespace,
	}, nil
}

// k8sGet performs an authenticated GET to the K8s API.
func (k *k8sClient) k8sGet(path string) ([]byte, int, error) {
	req, err := http.NewRequest("GET", k.apiServer+path, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Accept", "application/json")

	resp, err := k.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, err
}

// k8sPost performs an authenticated POST to the K8s API.
func (k *k8sClient) k8sPost(path string, jsonBody []byte) ([]byte, int, error) {
	req, err := http.NewRequest("POST", k.apiServer+path, strings.NewReader(string(jsonBody)))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := k.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, err
}

// k8sDelete performs an authenticated DELETE to the K8s API.
func (k *k8sClient) k8sDelete(path string) ([]byte, int, error) {
	req, err := http.NewRequest("DELETE", k.apiServer+path, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+k.token)

	resp, err := k.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, err
}
