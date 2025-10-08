package shadowaead2022

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/internal"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"github.com/shadowsocks/go-shadowsocks2/utils"
)

// ErrShortPacket means that the packet is too short for a valid encrypted packet.
var (
	ErrShortPacket      = errors.New("short packet")
	ErrInvalidSessionID = errors.New("invalid session ID")
	ErrReplayAttack     = errors.New("replay attack detected")
)

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

// UDPHeader represents the UDP header for both request and response
type UDPHeader struct {
	Type            byte       // HeaderTypeClientStream (0) or HeaderTypeServerStream (1)
	Timestamp       int64      // Unix epoch timestamp (8 bytes)
	ClientSessionID uint64     // Client session ID (8 bytes, only for response)
	PaddingLength   uint16     // Padding length (2 bytes)
	Address         socks.Addr // Target address (request) or Source address (response)
	Padding         []byte     // Random padding
}

// EncodeUDPHeader encodes UDP header for both request and response
func EncodeUDPHeader(header *UDPHeader) []byte {
	var totalLen int
	var buf []byte
	pos := 0

	if header.Type == HeaderTypeClientStream {
		// Request: Type (1) + Timestamp (8) + PaddingLength (2) + Address + Padding
		totalLen = 1 + 8 + 2 + len(header.Padding) + len(header.Address)
		buf = make([]byte, totalLen)

		buf[pos] = header.Type
		pos++

		binary.BigEndian.PutUint64(buf[pos:], uint64(header.Timestamp))
		pos += 8

		binary.BigEndian.PutUint16(buf[pos:], header.PaddingLength)
		pos += 2

		copy(buf[pos:], header.Padding)
		pos += len(header.Padding)

		copy(buf[pos:], header.Address)
	} else {
		// Response: Type (1) + Timestamp (8) + ClientSessionID (8) + PaddingLength (2) + Padding + Address
		totalLen = 1 + 8 + 8 + 2 + len(header.Padding) + len(header.Address)
		buf = make([]byte, totalLen)

		buf[pos] = header.Type
		pos++

		binary.BigEndian.PutUint64(buf[pos:], uint64(header.Timestamp))
		pos += 8

		binary.BigEndian.PutUint64(buf[pos:], header.ClientSessionID)
		pos += 8

		binary.BigEndian.PutUint16(buf[pos:], header.PaddingLength)
		pos += 2

		copy(buf[pos:], header.Padding)
		pos += len(header.Padding)

		copy(buf[pos:], header.Address)
	}

	return buf
}

// DecodeUDPHeader decodes UDP header for both request and response
func DecodeUDPHeader(data []byte) (*UDPHeader, error) {
	if len(data) < 11 { // Minimum: 1 + 8 + 2
		return nil, ErrInvalidHeader
	}

	header := &UDPHeader{}
	pos := 0

	header.Type = data[pos]
	pos++

	header.Timestamp = int64(binary.BigEndian.Uint64(data[pos:]))
	pos += 8

	if err := validateTimestamp(header.Timestamp); err != nil {
		return nil, err
	}

	if header.Type == HeaderTypeClientStream {
		// Request: PaddingLength + Address + Padding
		header.PaddingLength = binary.BigEndian.Uint16(data[pos:])
		pos += 2

		if header.PaddingLength < MinPaddingLength || header.PaddingLength > MaxPaddingLength {
			return nil, ErrInvalidHeader
		}

		// Extract address
		addr := socks.SplitAddr(data[pos:])
		if addr == nil {
			return nil, ErrInvalidHeader
		}
		header.Address = addr
		pos += len(addr)

		if len(data) < pos+int(header.PaddingLength) {
			return nil, ErrInvalidHeader
		}

		header.Padding = make([]byte, header.PaddingLength)
		copy(header.Padding, data[pos:pos+int(header.PaddingLength)])
	} else {
		// Response: ClientSessionID + PaddingLength + Padding + Address
		if len(data) < 19 { // 1 + 8 + 8 + 2
			return nil, ErrInvalidHeader
		}

		header.ClientSessionID = binary.BigEndian.Uint64(data[pos:])
		pos += 8

		header.PaddingLength = binary.BigEndian.Uint16(data[pos:])
		pos += 2

		if header.PaddingLength < MinPaddingLength || header.PaddingLength > MaxPaddingLength {
			return nil, ErrInvalidHeader
		}

		if len(data) < pos+int(header.PaddingLength) {
			return nil, ErrInvalidHeader
		}

		header.Padding = make([]byte, header.PaddingLength)
		copy(header.Padding, data[pos:pos+int(header.PaddingLength)])
		pos += int(header.PaddingLength)

		// Extract address
		addr := socks.SplitAddr(data[pos:])
		if addr == nil {
			return nil, ErrInvalidHeader
		}
		header.Address = addr
	}

	return header, nil
}

// NewSession creates a new UDP session with random session ID

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

// PackUDP encrypts plaintext using SIP022 UDP format (both request and response)
// Format: AES(separate_header) + AEAD(body)
func (c *PacketConn) PackUDP(dst, plaintext []byte) ([]byte, error) {
	salt := make([]byte, 8)
	binary.LittleEndian.AppendUint64(salt, c.session.SessionID)

	// Derive session subkey from salt for AEAD
	aead, err := c.Encrypter(salt)
	if err != nil {
		return nil, err
	}

	// Create separate header (session ID + packet ID)
	separateHeader := &SeparateHeader{
		SessionID: c.session.SessionID,
		PacketID:  c.session.GetNextPacketID(),
	}
	separateHeaderEncoding := EncodeSeparateHeader(separateHeader)

	// Encrypt separate header with AES using PSK
	encryptedSeparateHeader, err := encryptSeparateHeaderAES(separateHeader, c.psk)
	if err != nil {
		return nil, err
	}

	// Encode main header
	header := &UDPHeader{
		Type:          HeaderTypeClientStream,
		Timestamp:     time.Now().Unix(),
		PaddingLength: 0,
		Address:       c.targetAddr,
		Padding:       []byte{},
	}

	if c.isServer {
		header.ClientSessionID = c.clientSessionId
	}

	mainHeader := EncodeUDPHeader(header)

	// Combine main header + payload as body
	body := make([]byte, len(mainHeader)+len(plaintext))
	copy(body, mainHeader)
	copy(body[len(mainHeader):], plaintext)

	// Encrypt body with AEAD
	encryptedBody := aead.Seal(nil, separateHeaderEncoding[4:], body, nil)

	// Combine: encrypted_separate_header + encrypted_body
	totalSize := 16 + len(encryptedBody)
	if len(dst) < totalSize {
		return nil, io.ErrShortBuffer
	}

	pos := 0
	copy(dst[pos:], encryptedSeparateHeader)
	pos += 16
	copy(dst[pos:], encryptedBody)

	return dst[:totalSize], nil
}

// UnpackUDP decrypts pkt using SIP022 UDP format (both request and response)
// Format: AES(separate_header) + AEAD(body)
// Returns: (header, payload, sessionID, error)
func (c *PacketConn) UnpackUDP(dst, pkt []byte) (*UDPHeader, []byte, uint64, error) {
	// Decrypt separate header with AES using PSK
	encryptedSeparateHeader := pkt[:16]
	separateHeader, err := decryptSeparateHeaderAES(encryptedSeparateHeader, c.psk)
	if err != nil {
		return nil, nil, 0, err
	}
	separateHeaderEncoding := EncodeSeparateHeader(separateHeader)
	dst = append(dst, separateHeaderEncoding...)

	salt := make([]byte, 8)
	binary.LittleEndian.AppendUint64(salt, separateHeader.SessionID)

	// Validate session and packet ID
	// session, exists := sessions[separateHeader.SessionID]
	// if !exists {
	// 	if !createSession {
	// 		return nil, nil, 0, ErrInvalidSessionID
	// 	}
	// 	// New session - create it (server side)
	// 	session = &Session{
	// 		SessionID:    separateHeader.SessionID,
	// 		nextPacketID: 0,
	// 		lastSeen:     time.Now(),
	// 		replayWindow: make(map[uint64]bool),
	// 		windowSize:   1024,
	// 	}
	// 	sessions[separateHeader.SessionID] = session
	// }
	//
	// if !session.ValidatePacketID(separateHeader.PacketID) {
	// 	return nil, nil, separateHeader.SessionID, ErrReplayAttack
	// }

	// Derive session subkey from salt for AEAD
	aead, err := c.Decrypter(salt)
	if err != nil {
		return nil, nil, 0, err
	}

	// Decrypt body with AEAD
	encryptedBody := pkt[16:]
	if len(encryptedBody) < aead.Overhead() {
		return nil, nil, 0, ErrShortPacket
	}

	body, err := aead.Open(encryptedBody[:0], separateHeaderEncoding[4:], encryptedBody, nil)
	if err != nil {
		return nil, nil, 0, err
	}
	dst = append(dst, body...)

	// Parse main header from body
	header, err := DecodeUDPHeader(body)
	if err != nil {
		return nil, nil, 0, err
	}

	// Extract payload (everything after main header)
	var headerLen int
	if header.Type == HeaderTypeClientStream {
		headerLen = 1 + 8 + 2 + len(header.Address) + int(header.PaddingLength)
	} else {
		headerLen = 1 + 8 + 8 + 2 + int(header.PaddingLength) + len(header.Address)
	}
	if len(body) < headerLen {
		return nil, nil, 0, ErrShortPacket
	}
	payload := body[headerLen:]

	return header, payload, separateHeader.SessionID, nil
}

// packetConn implements SIP022 UDP with session management
type PacketConn struct {
	net.PacketConn
	internal.ShadowCipher
	sync.RWMutex
	buf             []byte // write buffer
	psk             []byte // pre-shared key for AES encryption
	clientSessionId uint64
	session         *utils.Session
	serverSessions  map[uint64]*utils.Session // for server-side session tracking
	isServer        bool
	targetAddr      socks.Addr // target address for client mode
}

// NewPacketConn wraps a net.PacketConn with SIP022 UDP session management
func NewPacketConn(c net.PacketConn, ciph internal.ShadowCipher, psk []byte, role int) *PacketConn {
	const maxPacketSize = 64 * 1024
	conn := &PacketConn{
		PacketConn:   c,
		ShadowCipher: ciph,
		buf:          make([]byte, maxPacketSize),
		session:      utils.NewSession(),
		isServer:     role == utils.ROLE_SERVER,
		psk:          psk,
	}

	switch role {
	case utils.ROLE_SERVER:
		conn.serverSessions = make(map[uint64]*utils.Session)
	}

	return conn
}

// SetTargetAddr sets the target address for client mode
func (c *PacketConn) SetTargetAddr(addr socks.Addr) {
	c.targetAddr = addr
}

// WriteTo encrypts b using SIP022 UDP format and writes to addr
func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.Lock()
	defer c.Unlock()

	if c.targetAddr == nil && !c.isServer {
		return 0, errors.New("target address not set")
	}

	buf, err := c.PackUDP(c.buf, b)
	if err != nil {
		return 0, err
	}
	_, err = c.PacketConn.WriteTo(buf, addr)
	return len(b), err
}

// WriteToUDPAddrPort encrypts b using SIP022 UDP format and writes to addr
// More efficient than WriteTo for UDP connections - avoids interface allocation
func (c *PacketConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	udpConn, ok := c.PacketConn.(*net.UDPConn)
	if !ok {
		return 0, errors.New("underlying connection is not *net.UDPConn")
	}

	c.Lock()
	defer c.Unlock()

	if c.targetAddr == nil && !c.isServer {
		return 0, errors.New("target address not set")
	}

	buf, err := c.PackUDP(c.buf, b)
	if err != nil {
		return 0, err
	}
	_, err = udpConn.WriteToUDPAddrPort(buf, addr)
	return len(b), err
}

// ReadFrom reads from the embedded PacketConn and decrypts using SIP022 UDP format
func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}

	c.Lock()
	defer c.Unlock()

	header, payload, _, err := c.UnpackUDP(b[0:], b[:n])
	if err != nil {
		return n, addr, err
	}

	// Store target address for potential use
	if c.isServer {
		c.targetAddr = header.Address
	}

	copy(b, payload)
	return len(payload), addr, nil
}

// ReadFromUDPAddrPort reads from UDP and decrypts using SIP022 UDP format
// More efficient than ReadFrom for UDP connections - avoids interface allocation
func (c *PacketConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	udpConn, ok := c.PacketConn.(*net.UDPConn)
	if !ok {
		return 0, netip.AddrPort{}, errors.New("underlying connection is not *net.UDPConn")
	}

	n, addr, err := udpConn.ReadFromUDPAddrPort(b)
	if err != nil {
		return n, addr, err
	}

	c.Lock()
	defer c.Unlock()

	header, payload, _, err := c.UnpackUDP(b[:0], b[:n])
	if err != nil {
		return n, addr, err
	}

	// Store target address for potential use
	if c.isServer {
		c.targetAddr = header.Address
	}

	copy(b, payload)
	return len(payload), addr, nil
}

// GetTargetAddr returns the target address from the last received packet
func (c *PacketConn) GetTargetAddr() socks.Addr {
	c.RLock()
	defer c.RUnlock()
	return c.targetAddr
}

func (c *PacketConn) GetSessionID() uint64 {
	c.RLock()
	defer c.RUnlock()
	return c.session.SessionID
}
