package main

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	shadowaead2022 "github.com/shadowsocks/go-shadowsocks2/shadowaead_2022"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"github.com/shadowsocks/go-shadowsocks2/utils"
)

type mode int

const (
	remoteServer mode = iota
	relayClient
	socksClient
)

const udpBufSize = 64 * 1024

// Listen on laddr for UDP packets, encrypt and send to server to reach target.
func udpLocal(laddr, server, target string, shadow func(net.PacketConn) net.PacketConn) {
	srvAddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		logf("UDP server address error: %v", err)
		return
	}

	tgt := socks.ParseAddr(target)
	if tgt == nil {
		err = fmt.Errorf("invalid target address: %q", target)
		logf("UDP target address error: %v", err)
		return
	}

	lnAddr, err := net.ResolveUDPAddr("udp", laddr)
	if err != nil {
		logf("UDP listen address error: %v", err)
		return
	}

	c, err := net.ListenUDP("udp", lnAddr)
	if err != nil {
		logf("UDP local listen error: %v", err)
		return
	}
	defer c.Close()

	nm := newNATmap(config.UDPTimeout)
	buf := make([]byte, udpBufSize)
	copy(buf, tgt)

	logf("UDP tunnel %s <-> %s <-> %s", laddr, server, target)
	for {
		n, raddr, err := c.ReadFromUDPAddrPort(buf[len(tgt):])
		if err != nil {
			logf("UDP local read error: %v", err)
			continue
		}

		pc := nm.Get(raddr)
		if pc == nil {
			pc, err = net.ListenPacket("udp", "")
			if err != nil {
				logf("UDP local listen error: %v", err)
				continue
			}

			pc = shadow(pc)
			nm.Add(raddr, c, pc, relayClient)
		}

		_, err = pc.WriteTo(buf[:len(tgt)+n], srvAddr)
		if err != nil {
			logf("UDP local write error: %v", err)
			continue
		}
	}
}

// Listen on laddr for Socks5 UDP packets, encrypt and send to server to reach target.
func udpSocksLocal(cipher, laddr, server string, shadow func(net.PacketConn, int) net.PacketConn) {
	srvAddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		logf("UDP server address error: %v", err)
		return
	}

	lnAddr, err := net.ResolveUDPAddr("udp", laddr)
	if err != nil {
		logf("UDP listen address error: %v", err)
		return
	}

	c, err := net.ListenUDP("udp", lnAddr)
	if err != nil {
		logf("UDP local listen error: %v", err)
		return
	}
	defer c.Close()

	sessionMap := newNATmap(config.UDPTimeout)
	sessionMap2022 := utils.NewSessionManager(config.UDPTimeout, udpBufSize)
	buf := make([]byte, udpBufSize)

	for {
		n, raddr, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			logf("UDP local read error: %v", err)
			continue
		}

		var pc net.PacketConn
		if strings.HasPrefix(cipher, "2022") {
			pc = sessionMap2022.GetByAddr(raddr)
		} else {
			pc = sessionMap.Get(raddr)
		}

		if pc == nil {
			pc, err = net.ListenPacket("udp", "")
			if err != nil {
				logf("UDP local listen error: %v", err)
				continue
			}

			tgt := socks.Addr(buf[3:])
			logf("UDP socks tunnel %s <-> %s <-> %s", laddr, server, tgt)
			pc = shadow(pc, utils.ROLE_CLIENT)
			if conn2022, ok := pc.(*shadowaead2022.PacketConn); ok {
				conn2022.SetTargetAddr(tgt)
				sessionMap2022.SetByAddr(raddr, pc, c, raddr)
			} else {
				sessionMap.Add(raddr, c, pc, socksClient)
			}
		}

		_, err = pc.WriteTo(buf[3:n], srvAddr)
		if err != nil {
			logf("UDP local write error: %v", err)
			continue
		}
	}
}

// Listen on addr for encrypted packets and basically do UDP NAT.
func udpRemote(cipher, addr string, shadow func(net.PacketConn, int) net.PacketConn) {
	nAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		logf("UDP server address error: %v", err)
		return
	}
	cc, err := net.ListenUDP("udp", nAddr)
	if err != nil {
		logf("UDP remote listen error: %v", err)
		return
	}
	defer cc.Close()
	c := shadow(cc, utils.ROLE_SERVER).(utils.UDPConn)

	sessionMap := newNATmap(config.UDPTimeout)
	sessionMap2022 := utils.NewSessionManager(config.UDPTimeout, udpBufSize)
	buf := make([]byte, udpBufSize)

	logf("listening UDP on %s", addr)
	for {
		n, raddr, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			logf("UDP remote read error: %v", err)
			continue
		}

		var tgtAddr socks.Addr

		if strings.HasPrefix(cipher, "2022") {
			conn2022 := c.(*shadowaead2022.PacketConn)
			tgtAddr = conn2022.GetTargetAddr()
		} else {
			tgtAddr = socks.SplitAddr(buf[:n])
		}
		if tgtAddr == nil {
			logf("failed to split target address from packet: %q", buf[:n])
			continue
		}

		tgtUDPAddr, err := net.ResolveUDPAddr("udp", tgtAddr.String())
		if err != nil {
			logf("failed to resolve target UDP address: %v", err)
			continue
		}

		var payload []byte
		if strings.HasPrefix(cipher, "2022") {
			payload = buf[:n]
		} else {
			payload = buf[len(tgtAddr):n]
		}

		var pc net.PacketConn
		if strings.HasPrefix(cipher, "2022") {
			conn2022 := c.(*shadowaead2022.PacketConn)
			pc = sessionMap2022.GetBySessionID(conn2022.GetSessionID())
		} else {
			pc = sessionMap.Get(raddr)
		}
		if pc == nil {
			pc, err = net.ListenPacket("udp", "")
			if err != nil {
				logf("UDP remote listen error: %v", err)
				continue
			}

			if strings.HasPrefix(cipher, "2022") {
				conn2022 := c.(*shadowaead2022.PacketConn)
				sessionMap2022.SetBySessionID(conn2022.GetSessionID(), pc, c, raddr)
			} else {
				sessionMap.Add(raddr, c, pc, remoteServer)
			}
		}

		_, err = pc.WriteTo(payload, tgtUDPAddr) // accept only UDPAddr despite the signature
		if err != nil {
			logf("UDP remote write error: %v", err)
			continue
		}
	}
}

// Packet NAT table
type natmap struct {
	sync.RWMutex
	m       map[netip.AddrPort]net.PacketConn
	timeout time.Duration
}

func newNATmap(timeout time.Duration) *natmap {
	m := &natmap{}
	m.m = make(map[netip.AddrPort]net.PacketConn)
	m.timeout = timeout
	return m
}

func (m *natmap) Get(key netip.AddrPort) net.PacketConn {
	m.RLock()
	defer m.RUnlock()
	return m.m[key]
}

func (m *natmap) Set(key netip.AddrPort, pc net.PacketConn) {
	m.Lock()
	defer m.Unlock()

	m.m[key] = pc
}

func (m *natmap) Del(key netip.AddrPort) net.PacketConn {
	m.Lock()
	defer m.Unlock()

	pc, ok := m.m[key]
	if ok {
		delete(m.m, key)
		return pc
	}
	return nil
}

func (m *natmap) Add(peer netip.AddrPort, dst utils.UDPConn, src net.PacketConn, role mode) {
	m.Set(peer, src)

	go func() {
		timedCopy(dst, peer, src, m.timeout, role)
		if pc := m.Del(peer); pc != nil {
			pc.Close()
		}
	}()
}

// copy from src to dst at target with read timeout
func timedCopy(dst utils.UDPConn, target netip.AddrPort, src net.PacketConn, timeout time.Duration, role mode) error {
	buf := make([]byte, udpBufSize)

	for {
		src.SetReadDeadline(time.Now().Add(timeout))
		n, raddr, err := src.ReadFrom(buf)
		if err != nil {
			return err
		}

		switch role {
		case remoteServer: // server -> client: add original packet source
			srcAddr := socks.ParseAddr(raddr.String())
			copy(buf[len(srcAddr):], buf[:n])
			copy(buf, srcAddr)
			_, err = dst.WriteToUDPAddrPort(buf[:len(srcAddr)+n], target)
		case relayClient: // client -> user: strip original packet source
			srcAddr := socks.SplitAddr(buf[:n])
			_, err = dst.WriteToUDPAddrPort(buf[len(srcAddr):n], target)
		case socksClient: // client -> socks5 program: just set RSV and FRAG = 0
			_, err = dst.WriteToUDPAddrPort(append([]byte{0, 0, 0}, buf[:n]...), target)
		}

		if err != nil {
			return err
		}
	}
}
