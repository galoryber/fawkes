package commands

import (
	"fmt"
	"strings"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
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

const (
	oidClientAuth       = "1.3.6.1.5.5.7.3.2"
	oidPKINITClient     = "1.3.6.1.5.2.3.4"
	oidSmartCardLogon   = "1.3.6.1.4.1.311.20.2.2"
	oidAnyPurpose       = "2.5.29.37.0"
	oidCertRequestAgent = "1.3.6.1.4.1.311.20.2.1"
	oidServerAuth       = "1.3.6.1.5.5.7.3.1"
)

const ctFlagEnrolleeSuppliesSubject = 1

var enrollmentGUID = guidToBytes("0e10c968-78fb-11d2-90d4-00c04f79dc55")

const (
	adsRightDSControlAccess = 0x00000100
	adsGenericAll           = 0x10000000
	adsWriteDACL            = 0x00040000
	adsWriteOwner           = 0x00080000
)

var lowPrivSIDMap = map[string]string{
	"S-1-1-0":      "Everyone",
	"S-1-5-11":     "Authenticated Users",
	"S-1-5-32-545": "BUILTIN\\Users",
}

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
