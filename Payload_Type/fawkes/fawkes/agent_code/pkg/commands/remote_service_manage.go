package commands

import (
	"fawkes/pkg/structs"

	svcctl "github.com/oiweiwei/go-msrpc/msrpc/scmr/svcctl/v2"
)

func remoteSvcCreate(args remoteServiceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: -name is required for create action")
	}
	if args.BinPath == "" {
		return errorResult("Error: -binpath is required for create action")
	}

	startType := parseStartType(args.StartType)
	displayName := args.DisplayName
	if displayName == "" {
		displayName = args.Name
	}

	cli, scm, ctx, cancel, cleanup, err := remoteSvcConnect(args, scManagerCreateService)
	if err != nil {
		return errorResult(err.Error())
	}
	defer cancel()
	defer cleanup()
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: scm}) }()

	createResp, err := cli.CreateServiceW(ctx, &svcctl.CreateServiceWRequest{
		ServiceManager: scm,
		ServiceName:    args.Name,
		DisplayName:    displayName,
		DesiredAccess:  svcAllAccess,
		ServiceType:    svcWin32OwnProcess,
		StartType:      startType,
		ErrorControl:   1, // SERVICE_ERROR_NORMAL
		BinaryPathName: args.BinPath,
	})
	if err != nil {
		return errorf("CreateServiceW failed: %v", err)
	}
	if createResp.Return != 0 {
		return errorf("CreateServiceW error: 0x%08x", createResp.Return)
	}
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: createResp.Service}) }()

	return successf("Service %q created on %s\n  Binary: %s\n  Start Type: %s", args.Name, args.Server, args.BinPath, remoteSvcStartTypeName(startType))
}

func remoteSvcStart(args remoteServiceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: -name is required for start action")
	}

	cli, scm, ctx, cancel, cleanup, err := remoteSvcConnect(args, scManagerConnect)
	if err != nil {
		return errorResult(err.Error())
	}
	defer cancel()
	defer cleanup()
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: scm}) }()

	svcResp, err := cli.OpenServiceW(ctx, &svcctl.OpenServiceWRequest{
		ServiceManager: scm,
		ServiceName:    args.Name,
		DesiredAccess:  svcStart | svcQueryStatus,
	})
	if err != nil {
		return errorf("Failed to open service %q: %v", args.Name, err)
	}
	if svcResp.Return != 0 {
		return errorf("OpenServiceW error: 0x%08x", svcResp.Return)
	}
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: svcResp.Service}) }()

	startResp, err := cli.StartServiceW(ctx, &svcctl.StartServiceWRequest{
		Service: svcResp.Service,
	})
	if err != nil {
		return errorf("StartServiceW failed: %v", err)
	}
	if startResp.Return != 0 {
		return errorf("StartServiceW error: 0x%08x", startResp.Return)
	}

	return successf("Service %q started on %s", args.Name, args.Server)
}

func remoteSvcStop(args remoteServiceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: -name is required for stop action")
	}

	cli, scm, ctx, cancel, cleanup, err := remoteSvcConnect(args, scManagerConnect)
	if err != nil {
		return errorResult(err.Error())
	}
	defer cancel()
	defer cleanup()
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: scm}) }()

	svcResp, err := cli.OpenServiceW(ctx, &svcctl.OpenServiceWRequest{
		ServiceManager: scm,
		ServiceName:    args.Name,
		DesiredAccess:  svcStop | svcQueryStatus,
	})
	if err != nil {
		return errorf("Failed to open service %q: %v", args.Name, err)
	}
	if svcResp.Return != 0 {
		return errorf("OpenServiceW error: 0x%08x", svcResp.Return)
	}
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: svcResp.Service}) }()

	ctrlResp, err := cli.ControlService(ctx, &svcctl.ControlServiceRequest{
		Service: svcResp.Service,
		Control: svcControlStop,
	})
	if err != nil {
		return errorf("ControlService(STOP) failed: %v", err)
	}
	if ctrlResp.Return != 0 {
		return errorf("ControlService(STOP) error: 0x%08x", ctrlResp.Return)
	}

	state := remoteSvcStateName(ctrlResp.ServiceStatus.CurrentState)
	return successf("Service %q stop requested on %s (current state: %s)", args.Name, args.Server, state)
}

func remoteSvcDelete(args remoteServiceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: -name is required for delete action")
	}

	cli, scm, ctx, cancel, cleanup, err := remoteSvcConnect(args, scManagerConnect)
	if err != nil {
		return errorResult(err.Error())
	}
	defer cancel()
	defer cleanup()
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: scm}) }()

	svcResp, err := cli.OpenServiceW(ctx, &svcctl.OpenServiceWRequest{
		ServiceManager: scm,
		ServiceName:    args.Name,
		DesiredAccess:  svcDelete,
	})
	if err != nil {
		return errorf("Failed to open service %q: %v", args.Name, err)
	}
	if svcResp.Return != 0 {
		return errorf("OpenServiceW error: 0x%08x", svcResp.Return)
	}
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: svcResp.Service}) }()

	delResp, err := cli.DeleteService(ctx, &svcctl.DeleteServiceRequest{
		Service: svcResp.Service,
	})
	if err != nil {
		return errorf("DeleteService failed: %v", err)
	}
	if delResp.Return != 0 {
		return errorf("DeleteService error: 0x%08x", delResp.Return)
	}

	return successf("Service %q marked for deletion on %s", args.Name, args.Server)
}
