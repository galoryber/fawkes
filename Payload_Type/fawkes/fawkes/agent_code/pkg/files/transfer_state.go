package files

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// TransferDirection indicates whether a transfer is upload or download
type TransferDirection int

const (
	TransferDownload TransferDirection = iota // Agent → Mythic (exfiltration)
	TransferUpload                            // Mythic → Agent (staging)
)

// TransferState tracks the state of an in-progress file transfer for resume support
type TransferState struct {
	FileID        string            // Mythic file_id for this transfer
	FullPath      string            // Source or destination path
	Direction     TransferDirection // Upload or download
	TotalChunks   int               // Total number of chunks
	LastChunk     int               // Last successfully transferred chunk number (1-indexed)
	RunningHash   []byte            // SHA256 state checkpoint (hash of all bytes so far)
	BytesSoFar    int64             // Total bytes transferred so far
}

// transferStateStore is an in-memory store for tracking resumable file transfers.
// Keyed by file path since the same file should only have one active transfer.
var transferStateStore = struct {
	sync.RWMutex
	states map[string]*TransferState
}{
	states: make(map[string]*TransferState),
}

// SaveTransferState saves or updates the transfer state for a file path.
func SaveTransferState(state *TransferState) {
	transferStateStore.Lock()
	defer transferStateStore.Unlock()
	transferStateStore.states[state.FullPath] = state
}

// GetTransferState returns the saved transfer state for a file path, if any.
func GetTransferState(fullPath string, direction TransferDirection) *TransferState {
	transferStateStore.RLock()
	defer transferStateStore.RUnlock()
	state, ok := transferStateStore.states[fullPath]
	if !ok || state.Direction != direction {
		return nil
	}
	return state
}

// ClearTransferState removes the saved transfer state for a file path.
func ClearTransferState(fullPath string) {
	transferStateStore.Lock()
	defer transferStateStore.Unlock()
	delete(transferStateStore.states, fullPath)
}

// StreamingHasher wraps sha256 computation for chunk-by-chunk hashing
type StreamingHasher struct {
	hash     [sha256.Size]byte
	hasher   interface{ Write([]byte) (int, error); Sum([]byte) []byte; Reset() }
	total    int64
}

// NewStreamingHasher creates a new streaming SHA256 hasher
func NewStreamingHasher() *StreamingHasher {
	return &StreamingHasher{
		hasher: sha256.New(),
	}
}

// Write adds data to the running hash
func (h *StreamingHasher) Write(data []byte) {
	h.hasher.Write(data)
	h.total += int64(len(data))
}

// Sum returns the hex-encoded SHA256 hash of all data written so far
func (h *StreamingHasher) Sum() string {
	return hex.EncodeToString(h.hasher.Sum(nil))
}

// BytesHashed returns the total bytes written to the hasher
func (h *StreamingHasher) BytesHashed() int64 {
	return h.total
}
