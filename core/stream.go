package core

import (
	"net"
	"github.com/shadowsocks/go-shadowsocks2/internal"
)

type listener struct {
	net.Listener
	internal.StreamConnCipher
}

func Listen(network, address string, ciph internal.StreamConnCipher) (net.Listener, error) {
	l, err := net.Listen(network, address)
	return &listener{l, ciph}, err
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	return l.StreamConn(c), err
}

func Dial(network, address string, ciph internal.StreamConnCipher) (net.Conn, error) {
	c, err := net.Dial(network, address)
	return ciph.StreamConn(c), err
}
