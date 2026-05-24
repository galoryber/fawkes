package commands

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type kubeconfigFile struct {
	APIVersion     string              `yaml:"apiVersion"`
	Kind           string              `yaml:"kind"`
	CurrentContext string              `yaml:"current-context"`
	Clusters       []kubeconfigCluster `yaml:"clusters"`
	Contexts       []kubeconfigContext `yaml:"contexts"`
	Users          []kubeconfigUser    `yaml:"users"`
}

type kubeconfigCluster struct {
	Name    string                    `yaml:"name"`
	Cluster kubeconfigClusterSettings `yaml:"cluster"`
}

type kubeconfigClusterSettings struct {
	Server                   string `yaml:"server"`
	CertificateAuthorityData string `yaml:"certificate-authority-data"`
	CertificateAuthority     string `yaml:"certificate-authority"`
	InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
}

type kubeconfigContext struct {
	Name    string                    `yaml:"name"`
	Context kubeconfigContextSettings `yaml:"context"`
}

type kubeconfigContextSettings struct {
	Cluster   string `yaml:"cluster"`
	User      string `yaml:"user"`
	Namespace string `yaml:"namespace"`
}

type kubeconfigUser struct {
	Name string                 `yaml:"name"`
	User kubeconfigUserSettings `yaml:"user"`
}

type kubeconfigUserSettings struct {
	Token                 string `yaml:"token"`
	ClientCertificateData string `yaml:"client-certificate-data"`
	ClientKeyData         string `yaml:"client-key-data"`
	ClientCertificate     string `yaml:"client-certificate"`
	ClientKey             string `yaml:"client-key"`
}

type kubeconfigAuth struct {
	APIServer         string
	Namespace         string
	Token             string
	CACert            []byte
	ClientCert        tls.Certificate
	HasClientCert     bool
	InsecureSkipVerify bool
}

func parseKubeconfig(data []byte) (*kubeconfigFile, error) {
	var kc kubeconfigFile
	if err := yaml.Unmarshal(data, &kc); err != nil {
		return nil, fmt.Errorf("invalid kubeconfig YAML: %w", err)
	}
	if kc.CurrentContext == "" && len(kc.Contexts) == 0 {
		return nil, fmt.Errorf("kubeconfig has no contexts")
	}
	return &kc, nil
}

func resolveKubeconfigAuth(kc *kubeconfigFile, contextName string) (*kubeconfigAuth, error) {
	if contextName == "" {
		contextName = kc.CurrentContext
	}
	if contextName == "" && len(kc.Contexts) > 0 {
		contextName = kc.Contexts[0].Name
	}

	var ctx *kubeconfigContextSettings
	for i := range kc.Contexts {
		if kc.Contexts[i].Name == contextName {
			ctx = &kc.Contexts[i].Context
			break
		}
	}
	if ctx == nil {
		return nil, fmt.Errorf("context %q not found in kubeconfig", contextName)
	}

	var cluster *kubeconfigClusterSettings
	for i := range kc.Clusters {
		if kc.Clusters[i].Name == ctx.Cluster {
			cluster = &kc.Clusters[i].Cluster
			break
		}
	}
	if cluster == nil {
		return nil, fmt.Errorf("cluster %q (from context %q) not found in kubeconfig", ctx.Cluster, contextName)
	}

	var user *kubeconfigUserSettings
	for i := range kc.Users {
		if kc.Users[i].Name == ctx.User {
			user = &kc.Users[i].User
			break
		}
	}
	if user == nil {
		return nil, fmt.Errorf("user %q (from context %q) not found in kubeconfig", ctx.User, contextName)
	}

	if cluster.Server == "" {
		return nil, fmt.Errorf("cluster %q has no server URL", ctx.Cluster)
	}

	auth := &kubeconfigAuth{
		APIServer:          strings.TrimRight(cluster.Server, "/"),
		Namespace:          ctx.Namespace,
		InsecureSkipVerify: cluster.InsecureSkipTLSVerify,
	}

	if auth.Namespace == "" {
		auth.Namespace = "default"
	}

	if caCert, err := loadPEMData(cluster.CertificateAuthorityData, cluster.CertificateAuthority); err == nil && len(caCert) > 0 {
		auth.CACert = caCert
	}

	auth.Token = user.Token

	certPEM, certErr := loadPEMData(user.ClientCertificateData, user.ClientCertificate)
	keyPEM, keyErr := loadPEMData(user.ClientKeyData, user.ClientKey)
	if certErr == nil && keyErr == nil && len(certPEM) > 0 && len(keyPEM) > 0 {
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("invalid client certificate/key: %w", err)
		}
		auth.ClientCert = cert
		auth.HasClientCert = true
	}

	if auth.Token == "" && !auth.HasClientCert {
		return nil, fmt.Errorf("user %q has no token or client certificate — exec-based auth is not supported; extract the token manually and use it in the kubeconfig", ctx.User)
	}

	return auth, nil
}

func loadPEMData(inlineBase64 string, filePath string) ([]byte, error) {
	if inlineBase64 != "" {
		return base64.StdEncoding.DecodeString(inlineBase64)
	}
	if filePath != "" {
		return os.ReadFile(filePath)
	}
	return nil, nil
}

func (auth *kubeconfigAuth) buildTLSConfig() *tls.Config {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	if auth.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	} else if len(auth.CACert) > 0 {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(auth.CACert)
		tlsConfig.RootCAs = pool
	}

	if auth.HasClientCert {
		tlsConfig.Certificates = []tls.Certificate{auth.ClientCert}
	}

	return tlsConfig
}
