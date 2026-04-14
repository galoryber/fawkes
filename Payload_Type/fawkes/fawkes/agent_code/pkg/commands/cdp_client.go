package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"
)

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
