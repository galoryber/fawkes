package commands

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// dohResponse represents the JSON wire format DNS response (RFC 8484).
type dohResponse struct {
	Status   int           `json:"Status"`
	TC       bool          `json:"TC"`       // Truncated
	RD       bool          `json:"RD"`       // Recursion Desired
	RA       bool          `json:"RA"`       // Recursion Available
	Question []dohQuestion `json:"Question"`
	Answer   []dohAnswer   `json:"Answer"`
}

type dohQuestion struct {
	Name string `json:"name"`
	Type int    `json:"type"`
}

type dohAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

// dohProviders maps well-known provider names to DOH endpoints.
var dohProviders = map[string]string{
	"cloudflare": "https://cloudflare-dns.com/dns-query",
	"google":     "https://dns.google/resolve",
	"quad9":      "https://dns.quad9.net:5053/dns-query",
}

// dnsDoH performs a DNS lookup via DNS-over-HTTPS (RFC 8484 JSON wire format).
// This bypasses traditional DNS monitoring since queries travel over HTTPS.
func dnsDoH(ctx context.Context, args dnsArgs) structs.CommandResult {
	if args.Target == "" {
		return errorResult("Error: target hostname is required")
	}

	// Determine record type
	recordType := "A"
	if args.Data != "" {
		recordType = strings.ToUpper(args.Data)
	}
	typeNum := dohTypeToNum(recordType)
	if typeNum == 0 {
		return errorf("Error: unsupported record type %q. Valid: A, AAAA, MX, TXT, NS, CNAME, SRV, SOA, PTR, ANY", recordType)
	}

	// Determine DOH server URL
	dohURL := dohProviders["cloudflare"] // default
	if args.Server != "" {
		if providerURL, ok := dohProviders[strings.ToLower(args.Server)]; ok {
			dohURL = providerURL
		} else if strings.HasPrefix(args.Server, "https://") {
			dohURL = args.Server
		} else {
			// Treat as a hostname — construct URL
			dohURL = fmt.Sprintf("https://%s/dns-query", args.Server)
		}
	}

	// Build query URL
	queryURL := fmt.Sprintf("%s?name=%s&type=%s", dohURL,
		url.QueryEscape(args.Target), url.QueryEscape(recordType))

	timeout := time.Duration(args.Timeout) * time.Second
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", queryURL, nil)
	if err != nil {
		return errorf("Error creating request: %v", err)
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := client.Do(req)
	if err != nil {
		return errorf("Error querying DOH server %s: %v", dohURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return errorf("Error reading response: %v", err)
	}

	if resp.StatusCode != 200 {
		return errorf("DOH server returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var dohResp dohResponse
	if err := json.Unmarshal(body, &dohResp); err != nil {
		return errorf("Error parsing DOH response: %v", err)
	}

	return formatDoHResult(args, recordType, dohURL, &dohResp)
}

// formatDoHResult formats the DOH response for display.
func formatDoHResult(args dnsArgs, recordType string, serverURL string, resp *dohResponse) structs.CommandResult {
	var sb strings.Builder

	// Extract provider name from URL for display
	provider := dohProviderName(serverURL)

	sb.WriteString(fmt.Sprintf("[*] DOH %s query for %s via %s\n", recordType, args.Target, provider))

	if resp.Status != 0 {
		rcodeNames := map[int]string{
			1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
			4: "NOTIMP", 5: "REFUSED",
		}
		name := rcodeNames[resp.Status]
		if name == "" {
			name = fmt.Sprintf("RCODE_%d", resp.Status)
		}
		return errorf("[!] DOH query failed: %s (status %d)", name, resp.Status)
	}

	if len(resp.Answer) == 0 {
		sb.WriteString("  (no records found)\n")
		return successResult(sb.String())
	}

	sb.WriteString(fmt.Sprintf("  %d record(s):\n", len(resp.Answer)))
	for _, ans := range resp.Answer {
		typeName := dohNumToType(ans.Type)
		sb.WriteString(fmt.Sprintf("  %-6s %-40s TTL=%-6d %s\n",
			typeName, ans.Name, ans.TTL, ans.Data))
	}

	if resp.TC {
		sb.WriteString("\n  [!] Response was truncated\n")
	}

	return successResult(sb.String())
}

// dohProviderName extracts a friendly name from a DOH URL.
func dohProviderName(serverURL string) string {
	for name, url := range dohProviders {
		if serverURL == url {
			return name
		}
	}
	// Extract hostname from URL
	if u, err := url.Parse(serverURL); err == nil {
		return u.Host
	}
	return serverURL
}

// dohTypeToNum converts a DNS record type string to its numeric value.
func dohTypeToNum(t string) int {
	types := map[string]int{
		"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12,
		"MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "ANY": 255,
	}
	return types[strings.ToUpper(t)]
}

// dohNumToType converts a numeric DNS record type to its string name.
func dohNumToType(n int) string {
	types := map[int]string{
		1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
		15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
	}
	if name, ok := types[n]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", n)
}
