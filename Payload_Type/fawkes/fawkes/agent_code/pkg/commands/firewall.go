//go:build windows
// +build windows

package commands

import (
	"encoding/json"
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

type firewallArgs struct {
	Action    string `json:"action"`
	Name      string `json:"name"`
	Direction string `json:"direction"`
	RuleAction string `json:"rule_action"`
	Protocol  string `json:"protocol"`
	Port      string `json:"port"`
	Program   string `json:"program"`
	Filter    string `json:"filter"`
	Enabled   string `json:"enabled"`
}

// Windows Firewall COM constants
const (
	// NET_FW_IP_PROTOCOL
	fwIPProtocolTCP = 6
	fwIPProtocolUDP = 17
	fwIPProtocolAny = 256

	// NET_FW_RULE_DIRECTION
	fwRuleDirectionIn  = 1
	fwRuleDirectionOut = 2

	// NET_FW_ACTION
	fwActionBlock = 0
	fwActionAllow = 1

	// NET_FW_PROFILE_TYPE2
	fwProfileDomain  = 1
	fwProfilePrivate = 2
	fwProfilePublic  = 4
	fwProfileAll     = 0x7FFFFFFF
)

func (c *FirewallCommand) Execute(task structs.Task) structs.CommandResult {
	var args firewallArgs

	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Actions: list, add, delete, enable, disable, status",
			Status:    "error",
			Completed: true,
		}
	}

	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: list, add, delete, enable, disable, status", args.Action),
			Status:    "error",
			Completed: true,
		}
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

// firewallStatus shows firewall profile status (enabled/disabled per profile).
func firewallStatus() structs.CommandResult {
	conn, cleanup, err := connectFirewall()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to firewall: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer cleanup()

	var sb strings.Builder
	sb.WriteString("Windows Firewall Status:\n\n")

	profiles := []struct {
		name    string
		profile int
	}{
		{"Domain", fwProfileDomain},
		{"Private", fwProfilePrivate},
		{"Public", fwProfilePublic},
	}

	for _, p := range profiles {
		enabledResult, err := oleutil.CallMethod(conn.policy, "get_FirewallEnabled", p.profile)
		if err != nil {
			sb.WriteString(fmt.Sprintf("  %-10s Error: %v\n", p.name+":", err))
			continue
		}
		enabled := enabledResult.Value()
		enabledResult.Clear()

		inResult, err := oleutil.CallMethod(conn.policy, "get_DefaultInboundAction", p.profile)
		inAction := "N/A"
		if err == nil {
			inAction = fwActionToString(inResult.Value())
			inResult.Clear()
		}

		outResult, err := oleutil.CallMethod(conn.policy, "get_DefaultOutboundAction", p.profile)
		outAction := "N/A"
		if err == nil {
			outAction = fwActionToString(outResult.Value())
			outResult.Clear()
		}

		sb.WriteString(fmt.Sprintf("  %-10s Enabled=%-5v  DefaultInbound=%-6s  DefaultOutbound=%s\n",
			p.name+":", enabled, inAction, outAction))
	}

	// Get rule count
	countResult, err := oleutil.GetProperty(conn.rules, "Count")
	if err == nil {
		sb.WriteString(fmt.Sprintf("\n  Total Rules: %v\n", countResult.Value()))
		countResult.Clear()
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// firewallList enumerates firewall rules, optionally filtered by name/direction/port.
func firewallList(args firewallArgs) structs.CommandResult {
	conn, cleanup, err := connectFirewall()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to firewall: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer cleanup()

	var sb strings.Builder
	sb.WriteString("Windows Firewall Rules:\n\n")
	sb.WriteString(fmt.Sprintf("%-45s %-5s %-8s %-6s %-8s %-15s %s\n",
		"Name", "Dir", "Action", "Proto", "Enabled", "LocalPorts", "Program"))
	sb.WriteString(strings.Repeat("-", 120) + "\n")

	filterLower := strings.ToLower(args.Filter)
	dirFilter := strings.ToLower(args.Direction)

	ruleCount := 0
	matchCount := 0

	err = oleutil.ForEach(conn.rules, func(v *ole.VARIANT) error {
		ruleDisp := v.ToIDispatch()
		ruleCount++

		nameResult, _ := oleutil.GetProperty(ruleDisp, "Name")
		name := ""
		if nameResult != nil {
			name = nameResult.ToString()
			nameResult.Clear()
		}

		// Apply name filter
		if filterLower != "" && !strings.Contains(strings.ToLower(name), filterLower) {
			return nil
		}

		dirResult, _ := oleutil.GetProperty(ruleDisp, "Direction")
		dir := ""
		dirVal := 0
		if dirResult != nil {
			dirVal = variantToInt(dirResult)
			dir = fwDirectionToString(dirVal)
			dirResult.Clear()
		}

		// Apply direction filter
		if dirFilter != "" {
			if dirFilter == "in" && dirVal != fwRuleDirectionIn {
				return nil
			}
			if dirFilter == "out" && dirVal != fwRuleDirectionOut {
				return nil
			}
		}

		actionResult, _ := oleutil.GetProperty(ruleDisp, "Action")
		action := ""
		if actionResult != nil {
			action = fwActionToString(actionResult.Value())
			actionResult.Clear()
		}

		protoResult, _ := oleutil.GetProperty(ruleDisp, "Protocol")
		proto := ""
		if protoResult != nil {
			proto = fwProtocolToString(variantToInt(protoResult))
			protoResult.Clear()
		}

		enabledResult, _ := oleutil.GetProperty(ruleDisp, "Enabled")
		enabled := ""
		if enabledResult != nil {
			enabled = fmt.Sprintf("%v", enabledResult.Value())
			enabledResult.Clear()
		}

		// Apply enabled filter
		if args.Enabled != "" {
			if strings.ToLower(args.Enabled) == "true" && enabled != "true" {
				return nil
			}
			if strings.ToLower(args.Enabled) == "false" && enabled != "false" {
				return nil
			}
		}

		portsResult, _ := oleutil.GetProperty(ruleDisp, "LocalPorts")
		ports := ""
		if portsResult != nil {
			ports = portsResult.ToString()
			if ports == "" || ports == "<nil>" {
				ports = "*"
			}
			portsResult.Clear()
		}

		// Apply port filter
		if args.Port != "" && ports != "*" && !strings.Contains(ports, args.Port) {
			return nil
		}

		progResult, _ := oleutil.GetProperty(ruleDisp, "ApplicationName")
		prog := ""
		if progResult != nil {
			prog = progResult.ToString()
			if prog == "<nil>" {
				prog = ""
			}
			progResult.Clear()
		}

		matchCount++
		if len(name) > 45 {
			name = name[:42] + "..."
		}
		if len(prog) > 40 {
			prog = "..." + prog[len(prog)-37:]
		}
		sb.WriteString(fmt.Sprintf("%-45s %-5s %-8s %-6s %-8s %-15s %s\n",
			name, dir, action, proto, enabled, ports, prog))
		return nil
	})

	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error enumerating rules: %v\n%s", err, sb.String()),
			Status:    "error",
			Completed: true,
		}
	}

	sb.WriteString(fmt.Sprintf("\nShowing %d/%d rules", matchCount, ruleCount))

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// firewallAdd creates a new firewall rule.
func firewallAdd(args firewallArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required for adding a rule",
			Status:    "error",
			Completed: true,
		}
	}

	conn, cleanup, err := connectFirewall()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to firewall: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer cleanup()

	// Create a new FwRule COM object
	ruleUnknown, err := oleutil.CreateObject("HNetCfg.FWRule")
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating FwRule: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	rule, err := ruleUnknown.QueryInterface(ole.IID_IDispatch)
	ruleUnknown.Release()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error querying FwRule IDispatch: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer rule.Release()

	// Set rule properties
	oleutil.PutProperty(rule, "Name", args.Name)
	oleutil.PutProperty(rule, "Enabled", true)
	oleutil.PutProperty(rule, "Profiles", fwProfileAll)

	// Direction (default: inbound)
	dir := fwRuleDirectionIn
	if strings.EqualFold(args.Direction, "out") || strings.EqualFold(args.Direction, "outbound") {
		dir = fwRuleDirectionOut
	}
	oleutil.PutProperty(rule, "Direction", dir)

	// Action (default: allow)
	action := fwActionAllow
	if strings.EqualFold(args.RuleAction, "block") {
		action = fwActionBlock
	}
	oleutil.PutProperty(rule, "Action", action)

	// Protocol
	proto := fwIPProtocolAny
	switch strings.ToLower(args.Protocol) {
	case "tcp":
		proto = fwIPProtocolTCP
	case "udp":
		proto = fwIPProtocolUDP
	}
	oleutil.PutProperty(rule, "Protocol", proto)

	// Ports (only for TCP/UDP)
	if args.Port != "" && (proto == fwIPProtocolTCP || proto == fwIPProtocolUDP) {
		oleutil.PutProperty(rule, "LocalPorts", args.Port)
	}

	// Program path
	if args.Program != "" {
		oleutil.PutProperty(rule, "ApplicationName", args.Program)
	}

	// Add the rule to the collection
	_, err = oleutil.CallMethod(conn.rules, "Add", rule)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error adding firewall rule: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Firewall rule added:\n"))
	sb.WriteString(fmt.Sprintf("  Name:      %s\n", args.Name))
	sb.WriteString(fmt.Sprintf("  Direction: %s\n", fwDirectionToString(dir)))
	sb.WriteString(fmt.Sprintf("  Action:    %s\n", fwActionToString(action)))
	sb.WriteString(fmt.Sprintf("  Protocol:  %s\n", fwProtocolToString(proto)))
	if args.Port != "" {
		sb.WriteString(fmt.Sprintf("  Port:      %s\n", args.Port))
	}
	if args.Program != "" {
		sb.WriteString(fmt.Sprintf("  Program:   %s\n", args.Program))
	}
	sb.WriteString("  Enabled:   true\n")
	sb.WriteString("  Profiles:  All\n")

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// firewallDelete removes a firewall rule by name.
func firewallDelete(args firewallArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required for deleting a rule",
			Status:    "error",
			Completed: true,
		}
	}

	conn, cleanup, err := connectFirewall()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to firewall: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer cleanup()

	_, err = oleutil.CallMethod(conn.rules, "Remove", args.Name)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error deleting firewall rule '%s': %v", args.Name, err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Deleted firewall rule: %s", args.Name),
		Status:    "success",
		Completed: true,
	}
}

// firewallEnableDisable enables or disables a rule by name.
func firewallEnableDisable(args firewallArgs, enable bool) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: name is required",
			Status:    "error",
			Completed: true,
		}
	}

	conn, cleanup, err := connectFirewall()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error connecting to firewall: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer cleanup()

	// Find the rule by iterating (COM rules collection doesn't have a direct Get-by-name for modification)
	found := false
	err = oleutil.ForEach(conn.rules, func(v *ole.VARIANT) error {
		ruleDisp := v.ToIDispatch()

		nameResult, _ := oleutil.GetProperty(ruleDisp, "Name")
		if nameResult == nil {
			return nil
		}
		name := nameResult.ToString()
		nameResult.Clear()

		if strings.EqualFold(name, args.Name) {
			_, putErr := oleutil.PutProperty(ruleDisp, "Enabled", enable)
			if putErr != nil {
				return putErr
			}
			found = true
		}
		return nil
	})

	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error modifying rule: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if !found {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Rule not found: %s", args.Name),
			Status:    "error",
			Completed: true,
		}
	}

	action := "Disabled"
	if enable {
		action = "Enabled"
	}
	return structs.CommandResult{
		Output:    fmt.Sprintf("%s firewall rule: %s", action, args.Name),
		Status:    "success",
		Completed: true,
	}
}

// Helper functions

func fwDirectionToString(dir int) string {
	switch dir {
	case fwRuleDirectionIn:
		return "In"
	case fwRuleDirectionOut:
		return "Out"
	default:
		return fmt.Sprintf("%d", dir)
	}
}

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

func fwActionIntToString(action int) string {
	switch action {
	case fwActionBlock:
		return "Block"
	case fwActionAllow:
		return "Allow"
	default:
		return fmt.Sprintf("%d", action)
	}
}

func fwProtocolToString(proto int) string {
	switch proto {
	case fwIPProtocolTCP:
		return "TCP"
	case fwIPProtocolUDP:
		return "UDP"
	case fwIPProtocolAny:
		return "Any"
	case 1:
		return "ICMPv4"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("%d", proto)
	}
}

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
