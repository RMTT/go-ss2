package shadowaead2022

import (
	"net"

	"github.com/shadowsocks/go-shadowsocks2/internal"
)

type streamConn struct {
	net.Conn
	internal.ShadowCipher
	r *reader
	w *writer
}

func (c *streamConn) Write(b []byte) (int, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.Write(b)
}

// NewConn wraps a stream-oriented net.Conn with cipher.
func NewConn(c net.Conn, ciph internal.ShadowCipher) net.Conn {
	return &streamConn{Conn: c, ShadowCipher: ciph}
}
