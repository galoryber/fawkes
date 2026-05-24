//go:build windows

package commands

import (
	"fmt"
	"strings"

	"fawkes/pkg/structs"
)

// PersistEnumCommand enumerates common Windows persistence mechanisms.
type PersistEnumCommand struct{}

func (c *PersistEnumCommand) Name() string { return "persist-enum" }
func (c *PersistEnumCommand) Description() string {
	return "Enumerate Windows persistence mechanisms — registry, startup, scheduled tasks, services, WMI (T1547)"
}

func (c *PersistEnumCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[persistEnumArgs](task)
	if parseErr != nil {
		return *parseErr
	}
	if args.Category == "" {
		args.Category = "all"
	}

	var sb strings.Builder
	sb.WriteString("=== Persistence Enumeration ===\n\n")

	cat := strings.ToLower(args.Category)
	found := 0

	if cat == "all" || cat == "registry" {
		found += persistEnumRegistry(&sb)
	}
	if cat == "all" || cat == "startup" {
		found += persistEnumStartupFolders(&sb)
	}
	if cat == "all" || cat == "winlogon" {
		found += persistEnumWinlogon(&sb)
	}
	if cat == "all" || cat == "ifeo" {
		found += persistEnumIFEO(&sb)
	}
	if cat == "all" || cat == "appinit" {
		found += persistEnumAppInit(&sb)
	}
	if cat == "all" || cat == "tasks" {
		found += persistEnumScheduledTasks(&sb)
	}
	if cat == "all" || cat == "services" {
		found += persistEnumServices(&sb)
	}
	if cat == "all" || cat == "portmonitors" {
		found += persistEnumPortMonitors(&sb)
	}

	sb.WriteString(fmt.Sprintf("\n=== Total: %d persistence items found ===\n", found))

	return successResult(sb.String())
}
