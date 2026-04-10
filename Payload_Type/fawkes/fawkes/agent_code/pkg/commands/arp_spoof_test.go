package commands

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestBuildARPReply(t *testing.T) {
	targetMAC, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	attackerMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	gatewayIP := net.ParseIP("192.168.1.1").To4()
	targetIP := net.ParseIP("192.168.1.100").To4()

	frame := buildARPReply(targetMAC, attackerMAC, gatewayIP, targetIP)

	// Verify frame length
	if len(frame) != arpPacketLen {
		t.Fatalf("Frame length = %d, expected %d", len(frame), arpPacketLen)
	}

	// Verify Ethernet header
	// Destination MAC = target
	for i := 0; i < 6; i++ {
		if frame[i] != targetMAC[i] {
			t.Errorf("Dst MAC byte %d = 0x%02X, expected 0x%02X", i, frame[i], targetMAC[i])
		}
	}
	// Source MAC = attacker
	for i := 0; i < 6; i++ {
		if frame[6+i] != attackerMAC[i] {
			t.Errorf("Src MAC byte %d = 0x%02X, expected 0x%02X", i, frame[6+i], attackerMAC[i])
		}
	}
	// EtherType = ARP (0x0806)
	etherType := binary.BigEndian.Uint16(frame[12:14])
	if etherType != 0x0806 {
		t.Errorf("EtherType = 0x%04X, expected 0x0806", etherType)
	}

	// Verify ARP header
	hwType := binary.BigEndian.Uint16(frame[14:16])
	if hwType != 1 {
		t.Errorf("HW Type = %d, expected 1 (Ethernet)", hwType)
	}
	protoType := binary.BigEndian.Uint16(frame[16:18])
	if protoType != 0x0800 {
		t.Errorf("Protocol Type = 0x%04X, expected 0x0800 (IPv4)", protoType)
	}
	if frame[18] != 6 {
		t.Errorf("HW Len = %d, expected 6", frame[18])
	}
	if frame[19] != 4 {
		t.Errorf("Proto Len = %d, expected 4", frame[19])
	}
	opcode := binary.BigEndian.Uint16(frame[20:22])
	if opcode != 2 {
		t.Errorf("Opcode = %d, expected 2 (Reply)", opcode)
	}

	// Verify sender = attacker MAC + gateway IP (what we're claiming)
	for i := 0; i < 6; i++ {
		if frame[22+i] != attackerMAC[i] {
			t.Errorf("Sender MAC byte %d = 0x%02X, expected 0x%02X", i, frame[22+i], attackerMAC[i])
		}
	}
	for i := 0; i < 4; i++ {
		if frame[28+i] != gatewayIP[i] {
			t.Errorf("Sender IP byte %d = %d, expected %d", i, frame[28+i], gatewayIP[i])
		}
	}

	// Verify target = target MAC + target IP
	for i := 0; i < 6; i++ {
		if frame[32+i] != targetMAC[i] {
			t.Errorf("Target MAC byte %d = 0x%02X, expected 0x%02X", i, frame[32+i], targetMAC[i])
		}
	}
	for i := 0; i < 4; i++ {
		if frame[38+i] != targetIP[i] {
			t.Errorf("Target IP byte %d = %d, expected %d", i, frame[38+i], targetIP[i])
		}
	}
}

func TestBuildARPReplyBidirectional(t *testing.T) {
	// Verify that building the reverse frame swaps sender/target correctly
	victimMAC, _ := net.ParseMAC("AA:BB:CC:DD:EE:FF")
	gatewayMAC, _ := net.ParseMAC("11:22:33:44:55:66")
	attackerMAC, _ := net.ParseMAC("DE:AD:BE:EF:CA:FE")
	victimIP := net.ParseIP("10.0.0.50").To4()
	gatewayIP := net.ParseIP("10.0.0.1").To4()

	// Frame 1: Tell victim that gateway has attacker's MAC
	frame1 := buildARPReply(victimMAC, attackerMAC, gatewayIP, victimIP)
	// Frame 2: Tell gateway that victim has attacker's MAC
	frame2 := buildARPReply(gatewayMAC, attackerMAC, victimIP, gatewayIP)

	// Frame 1: sender IP should be gateway
	for i := 0; i < 4; i++ {
		if frame1[28+i] != gatewayIP[i] {
			t.Errorf("Frame1 sender IP byte %d mismatch", i)
		}
	}
	// Frame 2: sender IP should be victim
	for i := 0; i < 4; i++ {
		if frame2[28+i] != victimIP[i] {
			t.Errorf("Frame2 sender IP byte %d mismatch", i)
		}
	}
	// Both frames: sender MAC should be attacker
	for i := 0; i < 6; i++ {
		if frame1[22+i] != attackerMAC[i] || frame2[22+i] != attackerMAC[i] {
			t.Errorf("Sender MAC byte %d should be attacker in both frames", i)
		}
	}
}

func TestParseArpSpoofArgs(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{
			"valid",
			`{"action":"spoof","target":"192.168.1.50","gateway":"192.168.1.1","duration":60}`,
			false,
		},
		{
			"missing target",
			`{"action":"spoof","gateway":"192.168.1.1"}`,
			true,
		},
		{
			"missing gateway",
			`{"action":"spoof","target":"192.168.1.50"}`,
			true,
		},
		{
			"invalid target IP",
			`{"action":"spoof","target":"not-an-ip","gateway":"192.168.1.1"}`,
			true,
		},
		{
			"defaults applied",
			`{"action":"spoof","target":"10.0.0.5","gateway":"10.0.0.1"}`,
			false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args, err := parseArpSpoofArgs(tc.json)
			if tc.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if args.Duration <= 0 {
				t.Error("Duration should have a default > 0")
			}
			if args.Interval <= 0 {
				t.Error("Interval should have a default > 0")
			}
		})
	}
}

func TestParseArpSpoofArgsDurationCap(t *testing.T) {
	args, err := parseArpSpoofArgs(`{"action":"spoof","target":"10.0.0.5","gateway":"10.0.0.1","duration":9999}`)
	if err != nil {
		t.Fatal(err)
	}
	if args.Duration > arpSpoofMaxDur {
		t.Errorf("Duration = %d, should be capped at %d", args.Duration, arpSpoofMaxDur)
	}
}
