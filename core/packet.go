package core

import (
	"net"
	"github.com/shadowsocks/go-shadowsocks2/internal"
)

func ListenPacket(network, address string, ciph internal.PacketConnCipher) (net.PacketConn, error) {
	c, err := net.ListenPacket(network, address)
	return ciph.PacketConn(c), err
}
