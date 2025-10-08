package utils

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Session manages UDP session
type Session struct {
	SessionID     uint64
	nextPacketID  uint64
	lastSeen      time.Time
	replayWindow  map[uint64]bool // sliding window for replay protection
	windowSize    uint64          // replay window size
	sessionSubkey []byte          // derived from PSK and session ID
	mutex         sync.RWMutex
}

func NewSession() *Session {
	sessionID := make([]byte, 8)
	rand.Read(sessionID)

	return &Session{
		SessionID:    binary.BigEndian.Uint64(sessionID),
		nextPacketID: 0,
		lastSeen:     time.Now(),
		replayWindow: make(map[uint64]bool),
		windowSize:   1024, // sliding window of 1024 packets
	}
}

// GetNextPacketID returns the next packet ID and increments counter
func (s *Session) GetNextPacketID() uint64 {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	packetID := s.nextPacketID
	s.nextPacketID++
	s.lastSeen = time.Now()
	return packetID
}

// ValidatePacketID checks if packet ID is valid and not a replay
func (s *Session) ValidatePacketID(packetID uint64) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check if packet is within sliding window
	if packetID < s.nextPacketID && s.nextPacketID-packetID > s.windowSize {
		return false // too old
	}

	// Check replay window
	if s.replayWindow[packetID] {
		return false // already seen
	}

	// Add to replay window
	s.replayWindow[packetID] = true

	// Clean up old entries
	if len(s.replayWindow) > int(s.windowSize) {
		for id := range s.replayWindow {
			if packetID > id && packetID-id > s.windowSize {
				delete(s.replayWindow, id)
			}
		}
	}

	// Update next expected packet ID if this is newer
	if packetID >= s.nextPacketID {
		s.nextPacketID = packetID + 1
	}

	s.lastSeen = time.Now()
	return true
}

type sessionMapKey struct {
	addr      netip.AddrPort
	sessionID uint64
}

type SessionManager struct {
	// session id/addr <-> PacketConn(include session info)
	sessions map[sessionMapKey]net.PacketConn
	timeout  time.Duration
	bufSize  uint64 // buf size for receiving packets from session connection
	mutex    sync.RWMutex
}

func NewSessionManager(timeout time.Duration, bufsize uint64) SessionManager {
	return SessionManager{
		sessions: make(map[sessionMapKey]net.PacketConn),
		timeout:  60 * time.Second,
		bufSize:  bufsize,
		mutex:    sync.RWMutex{},
	}
}

func (m *SessionManager) SetBySessionID(id uint64, conn net.PacketConn, dstConn net.PacketConn, dstTarget netip.AddrPort) {
	key := sessionMapKey{sessionID: id}

	m.mutex.Lock()
	m.sessions[key] = conn
	m.mutex.Unlock()

	go m.copy(key, conn, dstConn, dstTarget)
}

func (m *SessionManager) GetBySessionID(id uint64) net.PacketConn {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	key := sessionMapKey{sessionID: id}
	return m.sessions[key]
}

func (m *SessionManager) SetByAddr(addr netip.AddrPort, conn net.PacketConn, dstConn net.PacketConn, dstTarget netip.AddrPort) {
	key := sessionMapKey{addr: addr}
	m.mutex.Lock()
	m.sessions[key] = conn
	m.mutex.Unlock()

	go m.copy(key, conn, dstConn, dstTarget)
}

func (m *SessionManager) GetByAddr(addr netip.AddrPort) net.PacketConn {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	key := sessionMapKey{addr: addr}
	return m.sessions[key]
}

func (m *SessionManager) copy(key sessionMapKey, srcConn, dstConn net.PacketConn, dstTarget netip.AddrPort) error {
	buf := make([]byte, m.bufSize)

	defer func() {
		srcConn.Close()

		m.mutex.Lock()
		delete(m.sessions, key)
		m.mutex.Unlock()
	}()

	for {
		srcConn.SetReadDeadline(time.Now().Add(m.timeout))
		n, _, err := srcConn.ReadFrom(buf)
		if err != nil {
			return err
		}

		dstConn.(UDPConn).WriteToUDPAddrPort(buf[:n], dstTarget)
	}

	return nil
}
