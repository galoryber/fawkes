package commands

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
)

type AdcsCommand struct{}

func (c *AdcsCommand) Name() string { return "adcs" }
func (c *AdcsCommand) Description() string {
	return "Enumerate AD Certificate Services and find vulnerable templates"
}

type adcsArgs struct {
	Action   string `json:"action"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Hash     string `json:"hash"`
	Domain   string `json:"domain"`
	UseTLS   bool   `json:"use_tls"`
	CAName   string `json:"ca_name"`
	Template string `json:"template"`
	Subject  string `json:"subject"`
	AltName  string `json:"alt_name"`
	Timeout  int    `json:"timeout"`
}

// EKU OIDs relevant for ESC detection
const (
	oidClientAuth       = "1.3.6.1.5.5.7.3.2"
	oidPKINITClient     = "1.3.6.1.5.2.3.4"
	oidSmartCardLogon   = "1.3.6.1.4.1.311.20.2.2"
	oidAnyPurpose       = "2.5.29.37.0"
	oidCertRequestAgent = "1.3.6.1.4.1.311.20.2.1"
	oidServerAuth       = "1.3.6.1.5.5.7.3.1"
)

// Certificate name flag
const ctFlagEnrolleeSuppliesSubject = 1

// Certificate enrollment extended right GUID (mixed-endian binary)
var enrollmentGUID = guidToBytes("0e10c968-78fb-11d2-90d4-00c04f79dc55")

// Access mask constants
const (
	adsRightDSControlAccess = 0x00000100
	adsGenericAll           = 0x10000000
	adsWriteDACL            = 0x00040000
	adsWriteOwner           = 0x00080000
)

// Well-known low-privilege SIDs
var lowPrivSIDMap = map[string]string{
	"S-1-1-0":      "Everyone",
	"S-1-5-11":     "Authenticated Users",
	"S-1-5-32-545": "BUILTIN\\Users",
}

// Domain-relative RIDs for low-privilege groups
var lowPrivRIDMap = map[uint32]string{
	513: "Domain Users",
	515: "Domain Computers",
}

func (c *AdcsCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: parameters required. Use -action <cas|templates|find|request> -server <DC>")
	}

	args, parseErr := unmarshalParams[adcsArgs](task)
	if parseErr != nil {
		return *parseErr
	}
	defer zeroCredentials(&args.Password, &args.Hash)

	if args.Server == "" {
		return errorResult("Error: server parameter required (domain controller or CA server IP/hostname)")
	}

	// Request action uses DCOM (not LDAP) — handle separately
	if strings.ToLower(args.Action) == "request" {
		return adcsRequest(adcsRequestArgs{
			Server:   args.Server,
			Username: args.Username,
			Password: args.Password,
			Hash:     args.Hash,
			Domain:   args.Domain,
			CAName:   args.CAName,
			Template: args.Template,
			Subject:  args.Subject,
			AltName:  args.AltName,
			Timeout:  args.Timeout,
		})
	}

	if args.Port <= 0 {
		if args.UseTLS {
			args.Port = 636
		} else {
			args.Port = 389
		}
	}

	conn, err := adcsConnect(args)
	if err != nil {
		return errorf("Error connecting to LDAP %s:%d: %v", args.Server, args.Port, err)
	}
	defer conn.Close()

	if err := adcsBind(conn, args); err != nil {
		return errorf("Error binding to LDAP: %v", err)
	}

	configDN, baseDN, err := adcsGetConfigDN(conn)
	if err != nil {
		return errorf("Error detecting configuration DN: %v", err)
	}

	switch strings.ToLower(args.Action) {
	case "cas":
		return adcsEnumerateCAs(conn, configDN)
	case "templates":
		return adcsEnumerateTemplates(conn, configDN)
	case "find":
		return adcsFindVulnerable(conn, configDN, baseDN, args)
	default:
		return errorResult("Error: action must be one of: cas, templates, find, request")
	}
}

func adcsConnect(args adcsArgs) (*ldap.Conn, error) {
	return ldapDial(args.Server, args.Port, args.UseTLS)
}

func adcsBind(conn *ldap.Conn, args adcsArgs) error {
	return ldapBindSimple(conn, args.Username, args.Password)
}

func adcsGetConfigDN(conn *ldap.Conn) (string, string, error) {
	req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 10, false, "(objectClass=*)",
		[]string{"configurationNamingContext", "defaultNamingContext"}, nil)

	result, err := conn.Search(req)
	if err != nil {
		return "", "", fmt.Errorf("RootDSE query failed: %v", err)
	}
	if len(result.Entries) == 0 {
		return "", "", fmt.Errorf("no RootDSE entries returned")
	}

	configDN := result.Entries[0].GetAttributeValue("configurationNamingContext")
	baseDN := result.Entries[0].GetAttributeValue("defaultNamingContext")
	if configDN == "" {
		return "", "", fmt.Errorf("could not detect configurationNamingContext")
	}
	return configDN, baseDN, nil
}

// adcsEnumerateCAs lists all Certificate Authorities and their published templates
func adcsEnumerateCAs(conn *ldap.Conn, configDN string) structs.CommandResult {
	searchBase := fmt.Sprintf("CN=Enrollment Services,CN=Public Key Services,CN=Services,%s", configDN)

	req := ldap.NewSearchRequest(searchBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 30, false, "(objectCategory=pKIEnrollmentService)",
		[]string{"cn", "dNSHostName", "cACertificateDN", "certificateTemplates", "displayName"}, nil)

	result, err := conn.Search(req)
	if err != nil {
		return errorf("Error querying CAs: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Certificate Authorities (%d found)\n", len(result.Entries)))
	sb.WriteString(strings.Repeat("=", 60) + "\n")

	for i, entry := range result.Entries {
		sb.WriteString(fmt.Sprintf("\n[CA %d] %s\n", i+1, entry.GetAttributeValue("cn")))
		sb.WriteString(fmt.Sprintf("  DNS Name:    %s\n", entry.GetAttributeValue("dNSHostName")))
		sb.WriteString(fmt.Sprintf("  CA DN:       %s\n", entry.GetAttributeValue("cACertificateDN")))

		templates := entry.GetAttributeValues("certificateTemplates")
		sb.WriteString(fmt.Sprintf("  Templates:   %d published\n", len(templates)))
		for _, t := range templates {
			sb.WriteString(fmt.Sprintf("    - %s\n", t))
		}
	}

	if len(result.Entries) == 0 {
		sb.WriteString("\nNo Certificate Authorities found. ADCS may not be installed.\n")
	}

	return successResult(sb.String())
}

// adcsEnumerateTemplates lists all certificate templates with security-relevant attributes
func adcsEnumerateTemplates(conn *ldap.Conn, configDN string) structs.CommandResult {
	searchBase := fmt.Sprintf("CN=Certificate Templates,CN=Public Key Services,CN=Services,%s", configDN)

	req := ldap.NewSearchRequest(searchBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 30, false, "(objectClass=pKICertificateTemplate)",
		[]string{
			"cn", "displayName",
			"msPKI-Certificate-Name-Flag",
			"msPKI-Enrollment-Flag",
			"msPKI-RA-Signature",
			"pKIExtendedKeyUsage",
			"msPKI-Certificate-Application-Policy",
			"msPKI-Template-Schema-Version",
		}, nil)

	result, err := conn.SearchWithPaging(req, 100)
	if err != nil {
		return errorf("Error querying templates: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Certificate Templates (%d found)\n", len(result.Entries)))
	sb.WriteString(strings.Repeat("=", 60) + "\n")

	for i, entry := range result.Entries {
		name := entry.GetAttributeValue("cn")
		display := entry.GetAttributeValue("displayName")
		nameFlag := entry.GetAttributeValue("msPKI-Certificate-Name-Flag")
		raSig := entry.GetAttributeValue("msPKI-RA-Signature")
		ekus := entry.GetAttributeValues("pKIExtendedKeyUsage")
		appPolicies := entry.GetAttributeValues("msPKI-Certificate-Application-Policy")
		schemaVer := entry.GetAttributeValue("msPKI-Template-Schema-Version")

		sb.WriteString(fmt.Sprintf("\n[%d] %s", i+1, name))
		if display != "" && display != name {
			sb.WriteString(fmt.Sprintf(" (%s)", display))
		}
		sb.WriteString("\n")

		nameFlags, _ := strconv.ParseInt(nameFlag, 10, 64)
		if nameFlags&ctFlagEnrolleeSuppliesSubject != 0 {
			sb.WriteString("  Subject:     ENROLLEE_SUPPLIES_SUBJECT\n")
		} else {
			sb.WriteString("  Subject:     CA-provided\n")
		}

		allEKUs := append(ekus, appPolicies...) //nolint:gocritic // intentional: merge EKU lists
		if len(allEKUs) == 0 {
			sb.WriteString("  EKUs:        <none> (any purpose)\n")
		} else {
			ekuNames := make([]string, 0, len(allEKUs))
			for _, eku := range allEKUs {
				ekuNames = append(ekuNames, adcsResolveEKU(eku))
			}
			sb.WriteString(fmt.Sprintf("  EKUs:        %s\n", strings.Join(ekuNames, ", ")))
		}

		sb.WriteString(fmt.Sprintf("  RA Sigs:     %s\n", raSig))
		sb.WriteString(fmt.Sprintf("  Schema:      v%s\n", schemaVer))
	}

	return successResult(sb.String())
}

// adcsFindVulnerable checks published templates for ESC1-ESC4 vulnerabilities
// and queries each CA via DCOM for ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2).
func adcsFindVulnerable(conn *ldap.Conn, configDN, baseDN string, args adcsArgs) structs.CommandResult {
	// Get published templates from CAs (include dNSHostName for DCOM ESC6 check)
	caBase := fmt.Sprintf("CN=Enrollment Services,CN=Public Key Services,CN=Services,%s", configDN)
	caReq := ldap.NewSearchRequest(caBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 30, false, "(objectCategory=pKIEnrollmentService)",
		[]string{"cn", "certificateTemplates", "dNSHostName"}, nil)

	caResult, err := conn.Search(caReq)
	if err != nil {
		return errorf("Error querying CAs: %v", err)
	}

	// Build published template → CA name mapping
	publishedTemplates := make(map[string][]string)
	for _, ca := range caResult.Entries {
		caName := ca.GetAttributeValue("cn")
		for _, t := range ca.GetAttributeValues("certificateTemplates") {
			publishedTemplates[t] = append(publishedTemplates[t], caName)
		}
	}

	// Query templates with security descriptor for permission analysis
	templateBase := fmt.Sprintf("CN=Certificate Templates,CN=Public Key Services,CN=Services,%s", configDN)
	templateReq := ldap.NewSearchRequest(templateBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 30, false, "(objectClass=pKICertificateTemplate)",
		[]string{
			"cn", "displayName",
			"msPKI-Certificate-Name-Flag",
			"msPKI-Enrollment-Flag",
			"msPKI-RA-Signature",
			"pKIExtendedKeyUsage",
			"msPKI-Certificate-Application-Policy",
			"nTSecurityDescriptor",
		}, nil)

	templateResult, err := conn.SearchWithPaging(templateReq, 100)
	if err != nil {
		return errorf("Error querying templates: %v", err)
	}

	var sb strings.Builder
	sb.WriteString("ADCS Vulnerability Assessment\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n")
	sb.WriteString(fmt.Sprintf("CAs: %d | Templates: %d | Published: %d\n\n",
		len(caResult.Entries), len(templateResult.Entries), len(publishedTemplates)))

	vulnCount := 0

	for _, entry := range templateResult.Entries {
		name := entry.GetAttributeValue("cn")

		cas, published := publishedTemplates[name]
		if !published {
			continue
		}

		nameFlag := entry.GetAttributeValue("msPKI-Certificate-Name-Flag")
		raSig := entry.GetAttributeValue("msPKI-RA-Signature")
		ekus := entry.GetAttributeValues("pKIExtendedKeyUsage")
		appPolicies := entry.GetAttributeValues("msPKI-Certificate-Application-Policy")
		sdBytes := entry.GetRawAttributeValue("nTSecurityDescriptor")

		nameFlags, _ := strconv.ParseInt(nameFlag, 10, 64)
		raSigs, _ := strconv.ParseInt(raSig, 10, 64)
		allEKUs := append(ekus, appPolicies...) //nolint:gocritic // intentional: merge EKU lists

		// Parse enrollment and write permissions from SD
		enrollers := adcsParseEnrollmentPerms(sdBytes)
		lowPrivEnrollers := adcsFilterLowPriv(enrollers)
		writers := adcsParseWritePerms(sdBytes)
		lowPrivWriters := adcsFilterLowPriv(writers)

		var findings []string

		// ESC1: Enrollee supplies subject + auth EKU + low-priv enrollment + no manager approval
		if nameFlags&ctFlagEnrolleeSuppliesSubject != 0 && adcsHasAuthEKU(allEKUs) && raSigs == 0 && len(lowPrivEnrollers) > 0 {
			findings = append(findings, fmt.Sprintf("ESC1: Enrollee supplies subject + auth EKU + low-priv enrollment (%s)",
				strings.Join(lowPrivEnrollers, ", ")))
		}

		// ESC2: Any purpose or SubCA EKU + low-priv enrollment
		if (adcsHasAnyPurposeEKU(allEKUs) || len(allEKUs) == 0) && raSigs == 0 && len(lowPrivEnrollers) > 0 {
			findings = append(findings, fmt.Sprintf("ESC2: Any purpose/SubCA EKU + low-priv enrollment (%s)",
				strings.Join(lowPrivEnrollers, ", ")))
		}

		// ESC3: Certificate Request Agent EKU + low-priv enrollment
		if adcsHasCertRequestAgentEKU(allEKUs) && raSigs == 0 && len(lowPrivEnrollers) > 0 {
			findings = append(findings, fmt.Sprintf("ESC3: Certificate Request Agent + low-priv enrollment (%s)",
				strings.Join(lowPrivEnrollers, ", ")))
		}

		// ESC4: Low-priv user has write access to template
		if len(lowPrivWriters) > 0 {
			findings = append(findings, fmt.Sprintf("ESC4: Template writable by: %s",
				strings.Join(lowPrivWriters, ", ")))
		}

		if len(findings) > 0 {
			vulnCount++
			sb.WriteString(fmt.Sprintf("[!] %s (CA: %s)\n", name, strings.Join(cas, ", ")))
			for _, f := range findings {
				sb.WriteString(fmt.Sprintf("    %s\n", f))
			}
			if len(allEKUs) > 0 {
				ekuNames := make([]string, 0, len(allEKUs))
				for _, e := range allEKUs {
					ekuNames = append(ekuNames, adcsResolveEKU(e))
				}
				sb.WriteString(fmt.Sprintf("    EKUs: %s\n", strings.Join(ekuNames, ", ")))
			}
			sb.WriteString("\n")
		}
	}

	if vulnCount == 0 {
		sb.WriteString("No ESC1-ESC4 vulnerabilities found in published templates.\n")
	} else {
		sb.WriteString(fmt.Sprintf("Found %d vulnerable template(s)\n", vulnCount))
	}

	// ESC6: Check each CA for EDITF_ATTRIBUTESUBJECTALTNAME2 via DCOM
	if args.Username != "" && (args.Password != "" || args.Hash != "") {
		sb.WriteString("\n" + strings.Repeat("-", 60) + "\n")
		sb.WriteString("ESC6 Check (EDITF_ATTRIBUTESUBJECTALTNAME2)\n")
		sb.WriteString(strings.Repeat("-", 60) + "\n")

		domain := args.Domain
		username := args.Username
		if domain == "" {
			if parts := strings.SplitN(username, `\`, 2); len(parts) == 2 {
				domain = parts[0]
				username = parts[1]
			} else if parts := strings.SplitN(username, "@", 2); len(parts) == 2 {
				domain = parts[1]
				username = parts[0]
			}
		}
		cred, credErr := rpcCredential(username, domain, args.Password, args.Hash)
		structs.ZeroString(&args.Password)
		structs.ZeroString(&args.Hash)
		if credErr != nil {
			return errorf("Error: %v", credErr)
		}

		timeout := args.Timeout
		if timeout <= 0 {
			timeout = 30
		}

		for _, ca := range caResult.Entries {
			caName := ca.GetAttributeValue("cn")
			caHost := ca.GetAttributeValue("dNSHostName")
			if caHost == "" {
				sb.WriteString(fmt.Sprintf("  %s: SKIP (no dNSHostName in LDAP)\n", caName))
				continue
			}

			// Try dNSHostName first; if DNS resolution fails, fall back to LDAP server IP
			dcomTarget := caHost
			if _, lookupErr := net.LookupHost(caHost); lookupErr != nil {
				dcomTarget = args.Server
			}

			ctx, cancel := context.WithTimeout(
				gssapi.NewSecurityContext(context.Background()),
				time.Duration(timeout)*time.Second)
			editFlags, err := adcsQueryEditFlags(ctx, dcomTarget, caName, cred)
			cancel()

			if err != nil {
				sb.WriteString(fmt.Sprintf("  %s (%s): ERROR — %v\n", caName, dcomTarget, err))
				continue
			}

			if editFlags&editfAttributeSubjectAltName2 != 0 {
				vulnCount++
				sb.WriteString(fmt.Sprintf("[!] %s (%s): ESC6 VULNERABLE\n", caName, dcomTarget))
				sb.WriteString(fmt.Sprintf("    EditFlags: 0x%08x (EDITF_ATTRIBUTESUBJECTALTNAME2 is SET)\n", editFlags))
				sb.WriteString("    Any template with enrollment rights can be used for impersonation\n")
			} else {
				sb.WriteString(fmt.Sprintf("  %s (%s): EditFlags=0x%08x (ESC6 not vulnerable)\n", caName, dcomTarget, editFlags))
			}
		}
	} else {
		sb.WriteString("\nNote: ESC6 check requires credentials (-username/-password or -hash).\n")
		sb.WriteString("ESC8 (HTTP enrollment) requires manual verification.\n")
	}

	return successResult(sb.String())
}
