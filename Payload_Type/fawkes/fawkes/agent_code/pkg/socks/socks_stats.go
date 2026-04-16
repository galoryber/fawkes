package socks

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// ConnStats tracks connection statistics for SOCKS proxy monitoring.
type ConnStats struct {
	mu          sync.Mutex
	connections map[uint32]*ConnInfo
	history     []ConnInfo // completed connections (capped)
	maxHistory  int
}

// ConnInfo holds metadata about a single SOCKS connection.
type ConnInfo struct {
	ServerID    uint32    `json:"server_id"`
	Target      string    `json:"target"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time,omitempty"`
	BytesSent   int64     `json:"bytes_sent"`
	BytesRecv   int64     `json:"bytes_recv"`
	Status      string    `json:"status"` // "active", "closed", "error", "timeout"
}

// Duration returns the connection duration.
func (c *ConnInfo) Duration() time.Duration {
	if c.EndTime.IsZero() {
		return time.Since(c.StartTime)
	}
	return c.EndTime.Sub(c.StartTime)
}

// NewConnStats creates a connection statistics tracker.
func NewConnStats(maxHistory int) *ConnStats {
	if maxHistory <= 0 {
		maxHistory = 100
	}
	return &ConnStats{
		connections: make(map[uint32]*ConnInfo),
		maxHistory:  maxHistory,
	}
}

// RecordConnect records a new SOCKS connection.
func (s *ConnStats) RecordConnect(serverID uint32, target string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.connections[serverID] = &ConnInfo{
		ServerID:  serverID,
		Target:    target,
		StartTime: time.Now(),
		Status:    "active",
	}
}

// RecordSend records bytes sent through a connection.
func (s *ConnStats) RecordSend(serverID uint32, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if info, ok := s.connections[serverID]; ok {
		info.BytesSent += int64(n)
	}
}

// RecordRecv records bytes received from a connection.
func (s *ConnStats) RecordRecv(serverID uint32, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if info, ok := s.connections[serverID]; ok {
		info.BytesRecv += int64(n)
	}
}

// RecordClose records a connection closure.
func (s *ConnStats) RecordClose(serverID uint32, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, ok := s.connections[serverID]
	if !ok {
		return
	}
	info.EndTime = time.Now()
	info.Status = reason

	// Move to history
	s.history = append(s.history, *info)
	if len(s.history) > s.maxHistory {
		s.history = s.history[len(s.history)-s.maxHistory:]
	}
	delete(s.connections, serverID)
}

// ActiveCount returns the number of active connections.
func (s *ConnStats) ActiveCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.connections)
}

// Summary returns a JSON summary of active connections and recent history.
func (s *ConnStats) Summary() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	type summary struct {
		Active  []ConnInfo `json:"active"`
		Recent  []ConnInfo `json:"recent"`
		TotalTx int64      `json:"total_bytes_sent"`
		TotalRx int64      `json:"total_bytes_recv"`
	}

	var sm summary
	for _, info := range s.connections {
		sm.Active = append(sm.Active, *info)
		sm.TotalTx += info.BytesSent
		sm.TotalRx += info.BytesRecv
	}
	for _, info := range s.history {
		sm.TotalTx += info.BytesSent
		sm.TotalRx += info.BytesRecv
	}

	// Show last 10 from history
	start := len(s.history) - 10
	if start < 0 {
		start = 0
	}
	sm.Recent = s.history[start:]

	data, _ := json.Marshal(sm)
	return string(data)
}

// FormatSummary returns a human-readable summary string.
func (s *ConnStats) FormatSummary() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	active := len(s.connections)
	completed := len(s.history)

	var totalTx, totalRx int64
	for _, info := range s.connections {
		totalTx += info.BytesSent
		totalRx += info.BytesRecv
	}
	for _, info := range s.history {
		totalTx += info.BytesSent
		totalRx += info.BytesRecv
	}

	return fmt.Sprintf("SOCKS5 Proxy Stats: %d active, %d completed, TX: %s, RX: %s",
		active, completed, formatBytes(totalTx), formatBytes(totalRx))
}

func formatBytes(b int64) string {
	switch {
	case b >= 1024*1024*1024:
		return fmt.Sprintf("%.1f GB", float64(b)/(1024*1024*1024))
	case b >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	default:
		return fmt.Sprintf("%d B", b)
	}
}
