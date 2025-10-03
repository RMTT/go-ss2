package internal

import (
	"sync"
	"time"
)

// SIP022SaltFilter implements time-based salt filtering per SIP022 specification
// Salts are stored for exactly 60 seconds as required by the spec
type SIP022SaltFilter struct {
	salts           map[string]int64 // salt -> expiry timestamp
	mutex           sync.RWMutex
	stopCleanup     chan struct{}
	cleanupInterval time.Duration
}

// NewSIP022SaltFilter creates a new SIP022-compliant salt filter
func NewSIP022SaltFilter() *SIP022SaltFilter {
	sf := &SIP022SaltFilter{
		salts:           make(map[string]int64),
		stopCleanup:     make(chan struct{}),
		cleanupInterval: 10 * time.Second, // cleanup every 10 seconds
	}

	// Start cleanup routine
	go sf.cleanupRoutine()

	return sf
}

// Add adds a salt to the filter with 60-second expiry
func (sf *SIP022SaltFilter) Add(salt []byte) {
	sf.mutex.Lock()
	defer sf.mutex.Unlock()

	expiry := time.Now().Unix() + 60 // 60 seconds from now
	sf.salts[string(salt)] = expiry
}

// Test checks if a salt exists and is still valid (not expired)
func (sf *SIP022SaltFilter) Test(salt []byte) bool {
	sf.mutex.RLock()
	defer sf.mutex.RUnlock()

	expiry, exists := sf.salts[string(salt)]
	if !exists {
		return false
	}

	now := time.Now().Unix()
	if now > expiry {
		// Salt has expired, should be cleaned up
		return false
	}

	return true
}

// Check tests if salt exists, and if not, adds it. Returns true if salt was already present.
func (sf *SIP022SaltFilter) Check(salt []byte) bool {
	sf.mutex.Lock()
	defer sf.mutex.Unlock()

	saltStr := string(salt)
	expiry, exists := sf.salts[saltStr]
	now := time.Now().Unix()

	if exists && now <= expiry {
		// Salt exists and is still valid
		return true
	}

	// Add or update salt with new expiry
	sf.salts[saltStr] = now + 60
	return false
}

// cleanupRoutine removes expired salts periodically
func (sf *SIP022SaltFilter) cleanupRoutine() {
	ticker := time.NewTicker(sf.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sf.cleanupExpired()
		case <-sf.stopCleanup:
			return
		}
	}
}

// cleanup removes expired salts from the filter
func (sf *SIP022SaltFilter) cleanupExpired() {
	sf.mutex.Lock()
	defer sf.mutex.Unlock()

	now := time.Now().Unix()
	for salt, expiry := range sf.salts {
		if now > expiry {
			delete(sf.salts, salt)
		}
	}
}

// Close stops the cleanup routine
func (sf *SIP022SaltFilter) Close() {
	close(sf.stopCleanup)
}

// Global SIP022 salt filter instance
var sip022SaltFilter *SIP022SaltFilter
var initSIP022SaltFilterOnce sync.Once

// GetSIP022SaltFilter returns the global SIP022 salt filter instance
func GetSIP022SaltFilter() *SIP022SaltFilter {
	initSIP022SaltFilterOnce.Do(func() {
		sip022SaltFilter = NewSIP022SaltFilter()
	})
	return sip022SaltFilter
}

// CheckSaltSIP022 checks if a salt is repeated using SIP022 time-based filtering
func CheckSaltSIP022(salt []byte) bool {
	return GetSIP022SaltFilter().Check(salt)
}

// AddSaltSIP022 adds a salt to the SIP022 filter
func AddSaltSIP022(salt []byte) {
	GetSIP022SaltFilter().Add(salt)
}

