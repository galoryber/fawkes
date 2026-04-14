package commands

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// --- Minimal WebSocket client (RFC 6455) ---

type wsConn struct {
	conn   net.Conn
	reader *bufio.Reader
}

// wsDial performs a WebSocket handshake and returns a connection.
func wsDial(wsURL string) (*wsConn, error) {
	// Parse ws://host:port/path
	if !strings.HasPrefix(wsURL, "ws://") {
		return nil, fmt.Errorf("unsupported WebSocket scheme: %s", wsURL)
	}
	urlPart := wsURL[5:] // strip "ws://"
	slashIdx := strings.Index(urlPart, "/")
	host := urlPart
	path := "/"
	if slashIdx >= 0 {
		host = urlPart[:slashIdx]
		path = urlPart[slashIdx:]
	}

	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", host, err)
	}

	// Generate random WebSocket key
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		conn.Close()
		return nil, fmt.Errorf("generate ws key: %w", err)
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)

	// Send HTTP upgrade request
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send upgrade: %w", err)
	}

	// Read response
	reader := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	statusLine, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read status: %w", err)
	}
	if !strings.Contains(statusLine, "101") {
		conn.Close()
		return nil, fmt.Errorf("upgrade rejected: %s", strings.TrimSpace(statusLine))
	}

	// Consume remaining headers
	for {
		line, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
	}

	conn.SetDeadline(time.Time{}) // clear deadlines
	return &wsConn{conn: conn, reader: reader}, nil
}

// wsWriteText sends a text frame with client masking (RFC 6455 requirement).
func (w *wsConn) wsWriteText(data []byte) error {
	length := len(data)
	var header []byte

	// FIN + text opcode
	header = append(header, 0x81)

	// Length + mask bit
	switch {
	case length <= 125:
		header = append(header, byte(length)|0x80)
	case length <= 65535:
		header = append(header, 126|0x80, byte(length>>8), byte(length&0xff))
	default:
		header = append(header, 127|0x80)
		lenBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(lenBytes, uint64(length))
		header = append(header, lenBytes...)
	}

	// 4-byte mask key
	mask := make([]byte, 4)
	rand.Read(mask)
	header = append(header, mask...)

	// Mask payload
	masked := make([]byte, length)
	for i := range data {
		masked[i] = data[i] ^ mask[i%4]
	}

	w.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := w.conn.Write(header); err != nil {
		return err
	}
	_, err := w.conn.Write(masked)
	return err
}

// wsReadFrame reads a single WebSocket frame.
func (w *wsConn) wsReadFrame() ([]byte, int, error) {
	w.conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(w.reader, hdr); err != nil {
		return nil, 0, err
	}

	opcode := int(hdr[0] & 0x0f)
	masked := hdr[1]&0x80 != 0
	length := uint64(hdr[1] & 0x7f)

	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(w.reader, ext); err != nil {
			return nil, opcode, err
		}
		length = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(w.reader, ext); err != nil {
			return nil, opcode, err
		}
		length = binary.BigEndian.Uint64(ext)
	}

	// Safety limit: 16MB
	if length > 16*1024*1024 {
		return nil, opcode, fmt.Errorf("frame too large: %d bytes", length)
	}

	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(w.reader, maskKey); err != nil {
			return nil, opcode, err
		}
	}

	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(w.reader, payload); err != nil {
			return nil, opcode, err
		}
	}

	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return payload, opcode, nil
}

func (w *wsConn) close() {
	// Send close frame (opcode 8)
	w.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	closeFrame := []byte{0x88, 0x80, 0, 0, 0, 0} // FIN+close, masked, zero mask
	w.conn.Write(closeFrame)
	w.conn.Close()
}
