//go:build windows
// +build windows

// firewall.go implements the Windows Firewall command via COM API.
// Rule operations (list, add, delete, enable/disable, status) are in firewall_rules.go.

package commands

import (
	"fmt"
	"runtime"
	"strings"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"

	"fawkes/pkg/structs"
)

type FirewallCommand struct{}

func (c *FirewallCommand) Name() string {
	return "firewall"
}

func (c *FirewallCommand) Description() string {
	return "Manage Windows Firewall rules via COM API (HNetCfg.FwPolicy2)"
}

// fwIPProtocol*, fwRuleDirection*, fwAction* constants moved to command_helpers.go

// Windows Firewall COM constants (profile types)
const (
	// NET_FW_PROFILE_TYPE2
	fwProfileDomain  = 1
	fwProfilePrivate = 2
	fwProfilePublic  = 4
	fwProfileAll     = 0x7FFFFFFF
)

func (c *FirewallCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := requireParams[firewallArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	switch strings.ToLower(args.Action) {
	case "list":
		return firewallList(args)
	case "add":
		return firewallAdd(args)
	case "delete":
		return firewallDelete(args)
	case "enable":
		return firewallEnableDisable(args, true)
	case "disable":
		return firewallEnableDisable(args, false)
	case "status":
		return firewallStatus()
	default:
		return errorf("Unknown action: %s\nAvailable: list, add, delete, enable, disable, status", args.Action)
	}
}

// firewallConnection holds the FwPolicy2 COM interface.
type firewallConnection struct {
	policy *ole.IDispatch
	rules  *ole.IDispatch
}

// connectFirewall initializes COM and creates HNetCfg.FwPolicy2.
func connectFirewall() (*firewallConnection, func(), error) {
	runtime.LockOSThread()

	err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)
	if err != nil {
		oleErr, ok := err.(*ole.OleError)
		if !ok || (oleErr.Code() != ole.S_OK && oleErr.Code() != 0x00000001) {
			runtime.UnlockOSThread()
			return nil, nil, fmt.Errorf("CoInitializeEx failed: %v", err)
		}
	}

	unknown, err := oleutil.CreateObject("HNetCfg.FwPolicy2")
	if err != nil {
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, fmt.Errorf("failed to create HNetCfg.FwPolicy2: %v", err)
	}

	policy, err := unknown.QueryInterface(ole.IID_IDispatch)
	unknown.Release()
	if err != nil {
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, fmt.Errorf("failed to query IDispatch: %v", err)
	}

	rulesResult, err := oleutil.GetProperty(policy, "Rules")
	if err != nil {
		policy.Release()
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, fmt.Errorf("failed to get Rules collection: %v", err)
	}
	rules := rulesResult.ToIDispatch()

	conn := &firewallConnection{
		policy: policy,
		rules:  rules,
	}

	cleanup := func() {
		rules.Release()
		policy.Release()
		ole.CoUninitialize()
		runtime.UnlockOSThread()
	}

	return conn, cleanup, nil
}

// Helper functions

// fwDirectionToString moved to command_helpers.go

func fwActionToString(val interface{}) string {
	switch v := val.(type) {
	case int32:
		return fwActionIntToString(int(v))
	case int64:
		return fwActionIntToString(int(v))
	case int:
		return fwActionIntToString(v)
	case bool:
		if v {
			return "Allow"
		}
		return "Block"
	default:
		return fmt.Sprintf("%v", val)
	}
}

// fwActionIntToString, fwProtocolToString moved to command_helpers.go

func variantToInt(v *ole.VARIANT) int {
	if v == nil {
		return 0
	}
	switch val := v.Value().(type) {
	case int32:
		return int(val)
	case int64:
		return int(val)
	case int:
		return val
	default:
		return 0
	}
}
