package commands

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

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
