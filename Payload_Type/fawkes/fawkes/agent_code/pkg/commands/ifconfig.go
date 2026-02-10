package commands

import (
	"fmt"
	"net"
	"strings"

	"fawkes/pkg/structs"
)

type IfconfigCommand struct{}

func (c *IfconfigCommand) Name() string {
	return "ifconfig"
}

func (c *IfconfigCommand) Description() string {
	return "List network interfaces and their addresses"
}

func (c *IfconfigCommand) Execute(task structs.Task) structs.CommandResult {
	ifaces, err := net.Interfaces()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error enumerating interfaces: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var lines []string

	for _, iface := range ifaces {
		// Interface header
		flags := iface.Flags.String()
		line := fmt.Sprintf("%s: flags=<%s> mtu %d", iface.Name, flags, iface.MTU)
		lines = append(lines, line)

		// MAC address
		if len(iface.HardwareAddr) > 0 {
			lines = append(lines, fmt.Sprintf("    ether %s", iface.HardwareAddr))
		}

		// IP addresses
		addrs, err := iface.Addrs()
		if err != nil {
			lines = append(lines, fmt.Sprintf("    (error getting addresses: %v)", err))
			continue
		}

		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				if v.IP.To4() != nil {
					ones, _ := v.Mask.Size()
					lines = append(lines, fmt.Sprintf("    inet %s/%d", v.IP, ones))
				} else {
					ones, _ := v.Mask.Size()
					lines = append(lines, fmt.Sprintf("    inet6 %s/%d", v.IP, ones))
				}
			case *net.IPAddr:
				if v.IP.To4() != nil {
					lines = append(lines, fmt.Sprintf("    inet %s", v.IP))
				} else {
					lines = append(lines, fmt.Sprintf("    inet6 %s", v.IP))
				}
			default:
				lines = append(lines, fmt.Sprintf("    addr %s", addr.String()))
			}
		}

		lines = append(lines, "") // blank line between interfaces
	}

	output := strings.Join(lines, "\n")
	if output == "" {
		output = "No network interfaces found"
	}

	return structs.CommandResult{
		Output:    strings.TrimRight(output, "\n"),
		Status:    "success",
		Completed: true,
	}
}
