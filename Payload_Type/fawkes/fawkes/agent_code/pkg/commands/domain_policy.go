package commands

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
)

type DomainPolicyCommand struct{}

func (c *DomainPolicyCommand) Name() string { return "domain-policy" }
func (c *DomainPolicyCommand) Description() string {
	return "Enumerate AD domain password and lockout policies via LDAP (T1201)"
}

type domainPolicyArgs struct {
	Action   string `json:"action"`   // password, lockout, fgpp, all
	Server   string `json:"server"`   // DC IP/hostname
	Port     int    `json:"port"`     // optional (default: 389/636)
	Username string `json:"username"` // LDAP bind user (user@domain)
	Password string `json:"password"` // LDAP bind password
	BaseDN   string `json:"base_dn"`  // optional base DN
	UseTLS   bool   `json:"use_tls"`  // use LDAPS
}

func (c *DomainPolicyCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -action <password|lockout|fgpp|all> -server <DC> -username <user@domain> -password <pass>",
			Status:    "error",
			Completed: true,
		}
	}

	var args domainPolicyArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Action == "" {
		args.Action = "all"
	}
	if args.Server == "" {
		return structs.CommandResult{
			Output:    "Error: server parameter required (domain controller IP or hostname)",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Port <= 0 {
		if args.UseTLS {
			args.Port = 636
		} else {
			args.Port = 389
		}
	}

	// Connect
	conn, err := domainPolicyConnect(args)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to %s:%d: %v", args.Server, args.Port, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer conn.Close()

	// Bind
	if args.Username != "" && args.Password != "" {
		if err := conn.Bind(args.Username, args.Password); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error binding: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	} else {
		if err := conn.UnauthenticatedBind(""); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error anonymous bind: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	// Detect base DN
	baseDN := args.BaseDN
	if baseDN == "" {
		baseDN, err = domainPolicyDetectBaseDN(conn)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error detecting base DN: %v. Specify -base_dn manually.", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	var sb strings.Builder
	action := strings.ToLower(args.Action)

	switch action {
	case "password":
		sb.WriteString(queryDefaultPolicy(conn, baseDN, "password"))
	case "lockout":
		sb.WriteString(queryDefaultPolicy(conn, baseDN, "lockout"))
	case "fgpp":
		sb.WriteString(queryFGPPs(conn, baseDN))
	case "all":
		sb.WriteString(queryDefaultPolicy(conn, baseDN, "all"))
		sb.WriteString("\n")
		sb.WriteString(queryFGPPs(conn, baseDN))
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: password, lockout, fgpp, all", action),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func domainPolicyConnect(args domainPolicyArgs) (*ldap.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if args.UseTLS {
		return ldap.DialURL(fmt.Sprintf("ldaps://%s:%d", args.Server, args.Port),
			ldap.DialWithDialer(dialer),
			ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	}
	return ldap.DialURL(fmt.Sprintf("ldap://%s:%d", args.Server, args.Port),
		ldap.DialWithDialer(dialer))
}

func domainPolicyDetectBaseDN(conn *ldap.Conn) (string, error) {
	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 10, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	)
	result, err := conn.Search(searchRequest)
	if err != nil {
		return "", fmt.Errorf("RootDSE query failed: %v", err)
	}
	if len(result.Entries) == 0 {
		return "", fmt.Errorf("no RootDSE entries returned")
	}
	baseDN := result.Entries[0].GetAttributeValue("defaultNamingContext")
	if baseDN == "" {
		return "", fmt.Errorf("could not detect base DN")
	}
	return baseDN, nil
}

// queryDefaultPolicy queries the domain root object for password and lockout policy attributes.
func queryDefaultPolicy(conn *ldap.Conn, baseDN string, section string) string {
	attrs := []string{
		"minPwdLength", "maxPwdAge", "minPwdAge", "pwdHistoryLength",
		"pwdProperties", "lockoutThreshold", "lockoutDuration",
		"lockoutObservationWindow", "dc",
	}

	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 10, false,
		"(objectClass=domain)",
		attrs,
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		return fmt.Sprintf("[!] Error querying default domain policy: %v\n", err)
	}
	if len(result.Entries) == 0 {
		return "[!] No domain object found at base DN\n"
	}

	entry := result.Entries[0]
	var sb strings.Builder

	if section == "password" || section == "all" {
		sb.WriteString("[*] Default Domain Password Policy\n")
		sb.WriteString(strings.Repeat("-", 50) + "\n")

		minLen := entry.GetAttributeValue("minPwdLength")
		sb.WriteString(fmt.Sprintf("    Minimum Password Length:    %s\n", minLen))

		histLen := entry.GetAttributeValue("pwdHistoryLength")
		sb.WriteString(fmt.Sprintf("    Password History Length:    %s\n", histLen))

		maxAge := entry.GetAttributeValue("maxPwdAge")
		sb.WriteString(fmt.Sprintf("    Maximum Password Age:      %s\n", formatADInterval(maxAge)))

		minAge := entry.GetAttributeValue("minPwdAge")
		sb.WriteString(fmt.Sprintf("    Minimum Password Age:      %s\n", formatADInterval(minAge)))

		pwdProps := entry.GetAttributeValue("pwdProperties")
		sb.WriteString(fmt.Sprintf("    Password Complexity:       %s\n", formatPwdProperties(pwdProps)))
		sb.WriteString("\n")
	}

	if section == "lockout" || section == "all" {
		sb.WriteString("[*] Default Domain Lockout Policy\n")
		sb.WriteString(strings.Repeat("-", 50) + "\n")

		threshold := entry.GetAttributeValue("lockoutThreshold")
		sb.WriteString(fmt.Sprintf("    Lockout Threshold:         %s attempts\n", threshold))

		duration := entry.GetAttributeValue("lockoutDuration")
		sb.WriteString(fmt.Sprintf("    Lockout Duration:          %s\n", formatADInterval(duration)))

		window := entry.GetAttributeValue("lockoutObservationWindow")
		sb.WriteString(fmt.Sprintf("    Observation Window:        %s\n", formatADInterval(window)))

		// Spray-safe recommendation
		if threshold != "" && threshold != "0" {
			thresholdN, _ := strconv.Atoi(threshold)
			if thresholdN > 0 {
				safeAttempts := thresholdN - 2 // leave 2 as buffer
				if safeAttempts < 1 {
					safeAttempts = 1
				}
				windowDur := parseADInterval(window)
				sb.WriteString(fmt.Sprintf("\n    [+] Spray Recommendation:  max %d attempts per %s window\n", safeAttempts, formatDuration(windowDur)))
				if windowDur > 0 {
					delayMs := int(windowDur.Milliseconds()) / safeAttempts
					sb.WriteString(fmt.Sprintf("    [+] Suggested Delay:       %dms between attempts\n", delayMs))
				}
			}
		} else if threshold == "0" {
			sb.WriteString("\n    [+] No lockout threshold — unlimited spray attempts (no lockout policy)\n")
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// queryFGPPs queries Fine-Grained Password Policies from CN=Password Settings Container.
func queryFGPPs(conn *ldap.Conn, baseDN string) string {
	containerDN := fmt.Sprintf("CN=Password Settings Container,CN=System,%s", baseDN)

	attrs := []string{
		"cn", "msDS-PasswordSettingsPrecedence",
		"msDS-MinimumPasswordLength", "msDS-PasswordHistoryLength",
		"msDS-PasswordComplexityEnabled", "msDS-MinimumPasswordAge",
		"msDS-MaximumPasswordAge", "msDS-LockoutThreshold",
		"msDS-LockoutDuration", "msDS-LockoutObservationWindow",
		"msDS-PSOAppliesTo",
	}

	searchRequest := ldap.NewSearchRequest(
		containerDN,
		ldap.ScopeSingleLevel,
		ldap.NeverDerefAliases,
		0, 30, false,
		"(objectClass=msDS-PasswordSettings)",
		attrs,
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		// Container may not exist (pre-2008 domain, or no FGPPs configured)
		if strings.Contains(err.Error(), "No Such Object") {
			return "[*] Fine-Grained Password Policies: None found (no PSO container)\n"
		}
		return fmt.Sprintf("[!] Error querying FGPPs: %v\n", err)
	}

	if len(result.Entries) == 0 {
		return "[*] Fine-Grained Password Policies: None configured\n"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Fine-Grained Password Policies (%d found)\n", len(result.Entries)))
	sb.WriteString(strings.Repeat("-", 50) + "\n")

	for _, entry := range result.Entries {
		name := entry.GetAttributeValue("cn")
		sb.WriteString(fmt.Sprintf("\n  [PSO] %s\n", name))

		precedence := entry.GetAttributeValue("msDS-PasswordSettingsPrecedence")
		sb.WriteString(fmt.Sprintf("    Precedence:                %s\n", precedence))

		minLen := entry.GetAttributeValue("msDS-MinimumPasswordLength")
		sb.WriteString(fmt.Sprintf("    Minimum Password Length:    %s\n", minLen))

		histLen := entry.GetAttributeValue("msDS-PasswordHistoryLength")
		sb.WriteString(fmt.Sprintf("    Password History Length:    %s\n", histLen))

		complexity := entry.GetAttributeValue("msDS-PasswordComplexityEnabled")
		if complexity == "TRUE" {
			sb.WriteString("    Password Complexity:       Enabled\n")
		} else {
			sb.WriteString("    Password Complexity:       Disabled\n")
		}

		maxAge := entry.GetAttributeValue("msDS-MaximumPasswordAge")
		sb.WriteString(fmt.Sprintf("    Maximum Password Age:      %s\n", formatADInterval(maxAge)))

		minAge := entry.GetAttributeValue("msDS-MinimumPasswordAge")
		sb.WriteString(fmt.Sprintf("    Minimum Password Age:      %s\n", formatADInterval(minAge)))

		lockThreshold := entry.GetAttributeValue("msDS-LockoutThreshold")
		sb.WriteString(fmt.Sprintf("    Lockout Threshold:         %s attempts\n", lockThreshold))

		lockDuration := entry.GetAttributeValue("msDS-LockoutDuration")
		sb.WriteString(fmt.Sprintf("    Lockout Duration:          %s\n", formatADInterval(lockDuration)))

		lockWindow := entry.GetAttributeValue("msDS-LockoutObservationWindow")
		sb.WriteString(fmt.Sprintf("    Observation Window:        %s\n", formatADInterval(lockWindow)))

		appliesTo := entry.GetAttributeValues("msDS-PSOAppliesTo")
		if len(appliesTo) > 0 {
			sb.WriteString("    Applies To:\n")
			for _, dn := range appliesTo {
				sb.WriteString(fmt.Sprintf("      - %s\n", dn))
			}
		}
	}

	return sb.String()
}

// formatADInterval converts an AD large integer interval (100-nanosecond ticks, negative)
// to a human-readable duration string.
// AD stores durations as negative 100-ns intervals (e.g., -36000000000 = 1 hour).
func formatADInterval(val string) string {
	if val == "" {
		return "(not set)"
	}
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return val
	}
	if n == 0 {
		return "None (0)"
	}
	dur := parseADIntervalRaw(n)
	return formatDuration(dur)
}

// parseADInterval parses an AD interval string to a Go duration.
func parseADInterval(val string) time.Duration {
	if val == "" {
		return 0
	}
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return 0
	}
	return parseADIntervalRaw(n)
}

// parseADIntervalRaw converts a raw AD large integer (100-ns ticks, typically negative) to duration.
func parseADIntervalRaw(n int64) time.Duration {
	if n == math.MinInt64 {
		// Overflow protection — MinInt64 means "never expires" in AD
		return time.Duration(math.MaxInt64)
	}
	if n < 0 {
		n = -n
	}
	// AD uses 100-nanosecond ticks
	return time.Duration(n) * 100 * time.Nanosecond
}

// formatDuration formats a duration into human-readable "Xd Xh Xm" format.
func formatDuration(d time.Duration) string {
	if d == 0 {
		return "None (0)"
	}
	// Check for "never expires" (very large values)
	if d > 365*24*time.Hour*100 {
		return "Never"
	}

	days := int(d.Hours() / 24)
	hours := int(math.Mod(d.Hours(), 24))
	minutes := int(math.Mod(d.Minutes(), 60))

	parts := []string{}
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	if len(parts) == 0 {
		// Sub-minute duration
		secs := int(d.Seconds())
		if secs > 0 {
			return fmt.Sprintf("%ds", secs)
		}
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return strings.Join(parts, " ")
}

// formatPwdProperties interprets the pwdProperties bitmask.
func formatPwdProperties(val string) string {
	if val == "" {
		return "(not set)"
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return val
	}

	parts := []string{}
	if n&1 != 0 {
		parts = append(parts, "Complexity Required")
	} else {
		parts = append(parts, "No Complexity")
	}
	if n&2 != 0 {
		parts = append(parts, "Reversible Encryption")
	}

	return fmt.Sprintf("%s (%d)", strings.Join(parts, ", "), n)
}
