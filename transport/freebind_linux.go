//go:build linux

package transport

import (
	"syscall"
)

const (
	ipFreebind   = 15
	ipv6Freebind = 78
)

func applyFreebind(conn syscall.RawConn) {
	_ = conn.Control(func(fd uintptr) {
		s := int(fd)
		_ = syscall.SetsockoptInt(s, syscall.IPPROTO_IP, ipFreebind, 1)
		_ = syscall.SetsockoptInt(s, syscall.IPPROTO_IPV6, ipv6Freebind, 1)
	})
}
