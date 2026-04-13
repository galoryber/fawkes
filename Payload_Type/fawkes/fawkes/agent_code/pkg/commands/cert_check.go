package commands

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// CertCheckCommand inspects TLS certificates on remote hosts
type CertCheckCommand struct{}

func (c *CertCheckCommand) Name() string { return "cert-check" }
func (c *CertCheckCommand) Description() string {
	return "Inspect TLS certificates on remote hosts — identifies CAs, self-signed certs, expiry, SANs (T1590.001)"
}

type certCheckArgs struct {
	Host    string `json:"host"`    // Target host or host:port
	Port    int    `json:"port"`    // Port (default: 443)
	Timeout int    `json:"timeout"` // Timeout in seconds (default: 10)
}

func (c *CertCheckCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := requireParams[certCheckArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	if args.Host == "" {
		return errorResult("Error: host parameter is required")
	}
	if args.Port == 0 {
		args.Port = 443
	}
	if args.Timeout == 0 {
		args.Timeout = 10
	}

	addr := net.JoinHostPort(args.Host, fmt.Sprintf("%d", args.Port))
	timeout := time.Duration(args.Timeout) * time.Second

	// Connect with TLS, skip verification to inspect all certs
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return errorf("Error connecting to %s: %v", addr, err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return errorf("Connected to %s but no certificates presented", addr)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== TLS Certificate Check: %s ===\n\n", addr))

	// TLS version and cipher
	sb.WriteString(fmt.Sprintf("TLS Version:   %s\n", certTLSVersionName(state.Version)))
	sb.WriteString(fmt.Sprintf("Cipher Suite:  %s\n", tls.CipherSuiteName(state.CipherSuite)))
	sb.WriteString(fmt.Sprintf("Certificates:  %d in chain\n\n", len(state.PeerCertificates)))

	for i, cert := range state.PeerCertificates {
		if i == 0 {
			sb.WriteString("--- Leaf Certificate ---\n")
		} else {
			sb.WriteString(fmt.Sprintf("\n--- Certificate #%d (CA) ---\n", i+1))
		}
		sb.WriteString(certFormatCert(cert, args.Host))
	}

	return successResult(sb.String())
}

// certFormatCert formats a single X.509 certificate for display
func certFormatCert(cert *x509.Certificate, expectedHost string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("  Subject:     %s\n", cert.Subject.String()))
	sb.WriteString(fmt.Sprintf("  Issuer:      %s\n", cert.Issuer.String()))

	// Self-signed detection
	if cert.Subject.String() == cert.Issuer.String() {
		sb.WriteString("  Self-Signed: YES\n")
	}

	// Validity
	now := time.Now()
	sb.WriteString(fmt.Sprintf("  Not Before:  %s\n", cert.NotBefore.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("  Not After:   %s\n", cert.NotAfter.Format(time.RFC3339)))

	if now.Before(cert.NotBefore) { //nolint:gocritic // ifElseChain: clear temporal logic
		sb.WriteString("  Validity:    NOT YET VALID\n")
	} else if now.After(cert.NotAfter) {
		sb.WriteString("  Validity:    EXPIRED\n")
	} else {
		remaining := cert.NotAfter.Sub(now)
		sb.WriteString(fmt.Sprintf("  Validity:    OK (%d days remaining)\n", int(remaining.Hours()/24)))
	}

	// SANs
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 {
		sb.WriteString("  SANs:\n")
		for _, dns := range cert.DNSNames {
			sb.WriteString(fmt.Sprintf("    DNS: %s\n", dns))
		}
		for _, ip := range cert.IPAddresses {
			sb.WriteString(fmt.Sprintf("    IP:  %s\n", ip.String()))
		}
	}

	// Host match check (leaf cert only)
	if expectedHost != "" && !cert.IsCA {
		if err := cert.VerifyHostname(expectedHost); err != nil {
			sb.WriteString(fmt.Sprintf("  Host Match:  MISMATCH (%s)\n", err))
		} else {
			sb.WriteString("  Host Match:  OK\n")
		}
	}

	// Signature algorithm
	sb.WriteString(fmt.Sprintf("  Sig Algo:    %s\n", cert.SignatureAlgorithm.String()))

	// Key usage
	if cert.IsCA {
		sb.WriteString("  CA:          YES\n")
	}

	// Serial and fingerprint
	sb.WriteString(fmt.Sprintf("  Serial:      %s\n", cert.SerialNumber.String()))
	fingerprint := sha256.Sum256(cert.Raw)
	sb.WriteString(fmt.Sprintf("  SHA256:      %x\n", fingerprint))

	return sb.String()
}

// certTLSVersionName returns a human-readable TLS version name
func certTLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}
