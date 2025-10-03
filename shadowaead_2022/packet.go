package shadowaead2022

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/internal"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

// ErrShortPacket means that the packet is too short for a valid encrypted packet.
var (
	ErrShortPacket      = errors.New("short packet")
	ErrInvalidSessionID = errors.New("invalid session ID")
	ErrReplayAttack     = errors.New("replay attack detected")
)

var _zerononce [128]byte // read-only. 128 bytes is more than enough.

// SIP022UDPSession manages UDP session state per SIP022 specification
type SIP022UDPSession struct {
	SessionID      uint64
	nextPacketID   uint64
	lastSeen       time.Time
	replayWindow   map[uint64]bool // sliding window for replay protection
	windowSize     uint64          // replay window size
	sessionSubkey  []byte          // derived from PSK and session ID
	aeadEncrypter  cipher.AEAD     // AEAD for encrypting body
	aeadDecrypter  cipher.AEAD     // AEAD for decrypting body
	mutex          sync.RWMutex
}

// SeparateHeader represents the UDP separate header (16 bytes)
type SeparateHeader struct {
	SessionID uint64 // 8 bytes
	PacketID  uint64 // 8 bytes
}

// EncodeSeparateHeader encodes separate header to bytes
func EncodeSeparateHeader(header *SeparateHeader) []byte {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[0:8], header.SessionID)
	binary.BigEndian.PutUint64(buf[8:16], header.PacketID)
	return buf
}

// DecodeSeparateHeader decodes separate header from bytes
func DecodeSeparateHeader(data []byte) (*SeparateHeader, error) {
	if len(data) < 16 {
		return nil, ErrShortPacket
	}
	return &SeparateHeader{
		SessionID: binary.BigEndian.Uint64(data[0:8]),
		PacketID:  binary.BigEndian.Uint64(data[8:16]),
	}, nil
}

// UDPRequestHeader represents the UDP request main header
type UDPRequestHeader struct {
	Type            byte       // HeaderTypeClientStream (0)
	Timestamp       int64      // Unix epoch timestamp (8 bytes)
	PaddingLength   uint16     // Padding length (2 bytes)
	TargetAddress   socks.Addr // Target address
	Padding         []byte     // Random padding
}

// EncodeUDPRequestHeader encodes UDP request header
func EncodeUDPRequestHeader(header *UDPRequestHeader) []byte {
	// Type (1) + Timestamp (8) + PaddingLength (2) + Address + Padding
	totalLen := 1 + 8 + 2 + len(header.TargetAddress) + len(header.Padding)
	buf := make([]byte, totalLen)
	pos := 0

	buf[pos] = header.Type
	pos++

	binary.BigEndian.PutUint64(buf[pos:], uint64(header.Timestamp))
	pos += 8

	binary.BigEndian.PutUint16(buf[pos:], header.PaddingLength)
	pos += 2

	copy(buf[pos:], header.TargetAddress)
	pos += len(header.TargetAddress)

	copy(buf[pos:], header.Padding)

	return buf
}

// DecodeUDPRequestHeader decodes UDP request header
func DecodeUDPRequestHeader(data []byte) (*UDPRequestHeader, error) {
	if len(data) < 11 { // 1 + 8 + 2
		return nil, ErrInvalidHeader
	}

	header := &UDPRequestHeader{}
	pos := 0

	header.Type = data[pos]
	pos++

	header.Timestamp = int64(binary.BigEndian.Uint64(data[pos:]))
	pos += 8

	if err := validateTimestamp(header.Timestamp); err != nil {
		return nil, err
	}

	header.PaddingLength = binary.BigEndian.Uint16(data[pos:])
	pos += 2

	if header.PaddingLength < MinPaddingLength || header.PaddingLength > MaxPaddingLength {
		return nil, ErrInvalidHeader
	}

	// Extract target address
	addr := socks.SplitAddr(data[pos:])
	if addr == nil {
		return nil, ErrInvalidHeader
	}
	header.TargetAddress = addr
	pos += len(addr)

	if len(data) < pos+int(header.PaddingLength) {
		return nil, ErrInvalidHeader
	}

	header.Padding = make([]byte, header.PaddingLength)
	copy(header.Padding, data[pos:pos+int(header.PaddingLength)])

	return header, nil
}

// NewSIP022UDPSession creates a new UDP session with random session ID
func NewSIP022UDPSession() *SIP022UDPSession {
	sessionID := make([]byte, 8)
	rand.Read(sessionID)

	return &SIP022UDPSession{
		SessionID:    binary.BigEndian.Uint64(sessionID),
		nextPacketID: 0,
		lastSeen:     time.Now(),
		replayWindow: make(map[uint64]bool),
		windowSize:   1024, // sliding window of 1024 packets
	}
}

// GetNextPacketID returns the next packet ID and increments counter
func (s *SIP022UDPSession) GetNextPacketID() uint64 {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	packetID := s.nextPacketID
	s.nextPacketID++
	s.lastSeen = time.Now()
	return packetID
}

// ValidatePacketID checks if packet ID is valid and not a replay
func (s *SIP022UDPSession) ValidatePacketID(packetID uint64) bool {
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

// encryptSeparateHeaderAES encrypts separate header using AES block cipher with PSK
func encryptSeparateHeaderAES(header *SeparateHeader, psk []byte) ([]byte, error) {
	// Separate header is 16 bytes (session ID + packet ID)
	plainHeader := EncodeSeparateHeader(header)

	// Create AES cipher with PSK
	block, err := aes.NewCipher(psk)
	if err != nil {
		return nil, err
	}

	// Encrypt using AES ECB mode (single block)
	encrypted := make([]byte, 16)
	block.Encrypt(encrypted, plainHeader)

	return encrypted, nil
}

// decryptSeparateHeaderAES decrypts separate header using AES block cipher with PSK
func decryptSeparateHeaderAES(encrypted []byte, psk []byte) (*SeparateHeader, error) {
	if len(encrypted) != 16 {
		return nil, ErrShortPacket
	}

	// Create AES cipher with PSK
	block, err := aes.NewCipher(psk)
	if err != nil {
		return nil, err
	}

	// Decrypt using AES ECB mode (single block)
	decrypted := make([]byte, 16)
	block.Decrypt(decrypted, encrypted)

	return DecodeSeparateHeader(decrypted)
}

// PackSIP022UDP encrypts plaintext using SIP022 UDP format
// Format: salt + AES(separate_header) + AEAD(body)
func PackSIP022UDP(dst, plaintext []byte, targetAddr socks.Addr, ciph internal.ShadowCipher, session *SIP022UDPSession, psk []byte) ([]byte, error) {
	saltSize := ciph.SaltSize()
	salt := dst[:saltSize]
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	// Derive session subkey from salt for AEAD
	aead, err := ciph.Encrypter(salt)
	if err != nil {
		return nil, err
	}
	internal.AddSaltSIP022(salt)

	// Create separate header (session ID + packet ID)
	separateHeader := &SeparateHeader{
		SessionID: session.SessionID,
		PacketID:  session.GetNextPacketID(),
	}

	// Encrypt separate header with AES using PSK
	encryptedSeparateHeader, err := encryptSeparateHeaderAES(separateHeader, psk)
	if err != nil {
		return nil, err
	}

	// Create UDP request header (main header)
	padding := make([]byte, 0) // Can add random padding if needed
	requestHeader := &UDPRequestHeader{
		Type:          HeaderTypeClientStream,
		Timestamp:     time.Now().Unix(),
		PaddingLength: uint16(len(padding)),
		TargetAddress: targetAddr,
		Padding:       padding,
	}

	// Encode main header
	mainHeader := EncodeUDPRequestHeader(requestHeader)

	// Combine main header + payload as body
	body := make([]byte, len(mainHeader)+len(plaintext))
	copy(body, mainHeader)
	copy(body[len(mainHeader):], plaintext)

	// Encrypt body with AEAD
	encryptedBody := aead.Seal(nil, _zerononce[:aead.NonceSize()], body, nil)

	// Combine: salt + encrypted_separate_header + encrypted_body
	totalSize := saltSize + 16 + len(encryptedBody)
	if len(dst) < totalSize {
		return nil, io.ErrShortBuffer
	}

	pos := saltSize
	copy(dst[pos:], encryptedSeparateHeader)
	pos += 16
	copy(dst[pos:], encryptedBody)

	return dst[:totalSize], nil
}

// UnpackSIP022UDP decrypts pkt using SIP022 UDP format
// Format: salt + AES(separate_header) + AEAD(body)
// Returns: (targetAddr, payload, sessionID, error)
func UnpackSIP022UDP(dst, pkt []byte, ciph internal.ShadowCipher, sessions map[uint64]*SIP022UDPSession, psk []byte) (socks.Addr, []byte, uint64, error) {
	saltSize := ciph.SaltSize()
	if len(pkt) < saltSize+16 { // salt + separate header
		return nil, nil, 0, ErrShortPacket
	}

	salt := pkt[:saltSize]

	// Check salt replay
	if internal.CheckSaltSIP022(salt) {
		return nil, nil, 0, ErrRepeatedSalt
	}

	// Decrypt separate header with AES using PSK
	encryptedSeparateHeader := pkt[saltSize : saltSize+16]
	separateHeader, err := decryptSeparateHeaderAES(encryptedSeparateHeader, psk)
	if err != nil {
		return nil, nil, 0, err
	}

	// Validate session and packet ID
	session, exists := sessions[separateHeader.SessionID]
	if !exists {
		// New session - create it (server side)
		session = &SIP022UDPSession{
			SessionID:    separateHeader.SessionID,
			nextPacketID: 0,
			lastSeen:     time.Now(),
			replayWindow: make(map[uint64]bool),
			windowSize:   1024,
		}
		sessions[separateHeader.SessionID] = session
	}

	if !session.ValidatePacketID(separateHeader.PacketID) {
		return nil, nil, separateHeader.SessionID, ErrReplayAttack
	}

	// Derive session subkey from salt for AEAD
	aead, err := ciph.Decrypter(salt)
	if err != nil {
		return nil, nil, 0, err
	}

	// Decrypt body with AEAD
	encryptedBody := pkt[saltSize+16:]
	if len(encryptedBody) < aead.Overhead() {
		return nil, nil, 0, ErrShortPacket
	}

	body, err := aead.Open(dst[:0], _zerononce[:aead.NonceSize()], encryptedBody, nil)
	if err != nil {
		return nil, nil, 0, err
	}

	// Parse main header from body
	requestHeader, err := DecodeUDPRequestHeader(body)
	if err != nil {
		return nil, nil, 0, err
	}

	// Extract payload (everything after main header)
	headerLen := 1 + 8 + 2 + len(requestHeader.TargetAddress) + int(requestHeader.PaddingLength)
	if len(body) < headerLen {
		return nil, nil, 0, ErrShortPacket
	}
	payload := body[headerLen:]

	return requestHeader.TargetAddress, payload, separateHeader.SessionID, nil
}

// Pack encrypts plaintext using Cipher with a randomly generated salt and
// returns a slice of dst containing the encrypted packet and any error occurred.
// Ensure len(dst) >= ciph.SaltSize() + len(plaintext) + aead.Overhead().
func Pack(dst, plaintext []byte, ciph internal.ShadowCipher) ([]byte, error) {
	saltSize := ciph.SaltSize()
	salt := dst[:saltSize]
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	aead, err := ciph.Encrypter(salt)
	if err != nil {
		return nil, err
	}
	internal.AddSaltSIP022(salt)

	if len(dst) < saltSize+len(plaintext)+aead.Overhead() {
		return nil, io.ErrShortBuffer
	}
	b := aead.Seal(dst[saltSize:saltSize], _zerononce[:aead.NonceSize()], plaintext, nil)
	return dst[:saltSize+len(b)], nil
}

// Unpack decrypts pkt using Cipher and returns a slice of dst containing the decrypted payload and any error occurred.
// Ensure len(dst) >= len(pkt) - aead.SaltSize() - aead.Overhead().
func Unpack(dst, pkt []byte, ciph internal.ShadowCipher) ([]byte, error) {
	saltSize := ciph.SaltSize()
	if len(pkt) < saltSize {
		return nil, ErrShortPacket
	}
	salt := pkt[:saltSize]
	aead, err := ciph.Decrypter(salt)
	if err != nil {
		return nil, err
	}
	if internal.CheckSaltSIP022(salt) {
		return nil, ErrRepeatedSalt
	}
	if len(pkt) < saltSize+aead.Overhead() {
		return nil, ErrShortPacket
	}
	if saltSize+len(dst)+aead.Overhead() < len(pkt) {
		return nil, io.ErrShortBuffer
	}
	b, err := aead.Open(dst[:0], _zerononce[:aead.NonceSize()], pkt[saltSize:], nil)
	return b, err
}

type packetConn struct {
	net.PacketConn
	internal.ShadowCipher
	sync.Mutex
	buf []byte // write lock
}

// SIP022PacketConn implements SIP022 UDP with session management
type SIP022PacketConn struct {
	net.PacketConn
	internal.ShadowCipher
	sync.RWMutex
	buf            []byte                       // write buffer
	psk            []byte                       // pre-shared key for AES encryption
	clientSession  *SIP022UDPSession            // for client-side
	serverSessions map[uint64]*SIP022UDPSession // for server-side session tracking
	isServer       bool
	targetAddr     socks.Addr // target address for client mode
}

// NewPacketConn wraps a net.PacketConn with cipher
func NewPacketConn(c net.PacketConn, ciph internal.ShadowCipher) net.PacketConn {
	const maxPacketSize = 64 * 1024
	if cc, ok := c.(*net.UDPConn); ok {
		return &udpConn{UDPConn: cc, ShadowCipher: ciph, buf: make([]byte, maxPacketSize)}
	}
	return &packetConn{PacketConn: c, ShadowCipher: ciph, buf: make([]byte, maxPacketSize)}
}

// NewSIP022PacketConn wraps a net.PacketConn with SIP022 UDP session management
func NewSIP022PacketConn(c net.PacketConn, ciph internal.ShadowCipher, psk []byte, isServer bool) *SIP022PacketConn {
	const maxPacketSize = 64 * 1024
	conn := &SIP022PacketConn{
		PacketConn:     c,
		ShadowCipher:   ciph,
		buf:            make([]byte, maxPacketSize),
		psk:            psk,
		isServer:       isServer,
		serverSessions: make(map[uint64]*SIP022UDPSession),
	}

	if !isServer {
		conn.clientSession = NewSIP022UDPSession()
	}

	return conn
}

// SetTargetAddr sets the target address for client mode
func (c *SIP022PacketConn) SetTargetAddr(addr socks.Addr) {
	c.targetAddr = addr
}

// WriteTo encrypts b using SIP022 UDP format and writes to addr
func (c *SIP022PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.Lock()
	defer c.Unlock()

	if c.clientSession == nil {
		return 0, errors.New("no client session available")
	}

	if c.targetAddr == nil {
		return 0, errors.New("target address not set")
	}

	buf, err := PackSIP022UDP(c.buf, b, c.targetAddr, c.ShadowCipher, c.clientSession, c.psk)
	if err != nil {
		return 0, err
	}
	_, err = c.PacketConn.WriteTo(buf, addr)
	return len(b), err
}

// ReadFrom reads from the embedded PacketConn and decrypts using SIP022 UDP format
func (c *SIP022PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}

	c.Lock()
	defer c.Unlock()

	targetAddr, payload, sessionID, err := UnpackSIP022UDP(b[c.ShadowCipher.SaltSize():], b[:n], c.ShadowCipher, c.serverSessions, c.psk)
	if err != nil {
		return n, addr, err
	}

	// Store target address for potential use
	if c.isServer {
		c.targetAddr = targetAddr
	}

	copy(b, payload)
	return len(payload), addr, nil
}

// GetTargetAddr returns the target address from the last received packet
func (c *SIP022PacketConn) GetTargetAddr() socks.Addr {
	c.RLock()
	defer c.RUnlock()
	return c.targetAddr
}

// WriteTo encrypts b and write to addr using the embedded PacketConn.
func (c *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.Lock()
	defer c.Unlock()
	buf, err := Pack(c.buf, b, c.ShadowCipher)
	if err != nil {
		return 0, err
	}
	_, err = c.PacketConn.WriteTo(buf, addr)
	return len(b), err
}

// ReadFrom reads from the embedded PacketConn and decrypts into b.
func (c *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}
	bb, err := Unpack(b[c.ShadowCipher.SaltSize():], b[:n], c.ShadowCipher)
	if err != nil {
		return n, addr, err
	}
	copy(b, bb)
	return len(bb), addr, err
}

type udpConn struct {
	*net.UDPConn
	internal.ShadowCipher
	sync.Mutex
	buf []byte // write lock
}

// WriteTo encrypts b and write to addr using the embedded UDPConn.
func (c *udpConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.Lock()
	defer c.Unlock()
	buf, err := Pack(c.buf, b, c.ShadowCipher)
	if err != nil {
		return 0, err
	}
	_, err = c.UDPConn.WriteTo(buf, addr)
	return len(b), err
}

// ReadFrom reads from the embedded UDPConn and decrypts into b.
func (c *udpConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.UDPConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}
	bb, err := Unpack(b[c.ShadowCipher.SaltSize():], b[:n], c.ShadowCipher)
	if err != nil {
		return n, addr, err
	}
	copy(b, bb)
	return len(bb), addr, err
}

// WriteToUDPAddrPort encrypts b and write to addr using the embedded PacketConn.
func (c *udpConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	c.Lock()
	defer c.Unlock()
	buf, err := Pack(c.buf, b, c.ShadowCipher)
	if err != nil {
		return 0, err
	}
	_, err = c.UDPConn.WriteToUDPAddrPort(buf, addr)
	return len(b), err
}

// ReadFromUDPAddrPort reads from the embedded UDPConn and decrypts into b.
func (c *udpConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	n, addr, err := c.UDPConn.ReadFromUDPAddrPort(b)
	if err != nil {
		return n, addr, err
	}
	bb, err := Unpack(b[c.ShadowCipher.SaltSize():], b[:n], c.ShadowCipher)
	if err != nil {
		return n, addr, err
	}
	copy(b, bb)
	return len(bb), addr, err
}
