//go:build linux

package transport

import (
	"fmt"
	"syscall"

	"github.com/jesterfoidchopped/akamai-v3-sensor/fingerprint"
)

const tcpWindowClamp = 10

func applyTCPFingerprint(conn syscall.RawConn, fp *fingerprint.TCPFingerprint) error {
	var sysErr error
	err := conn.Control(func(fd uintptr) {
		s := int(fd)

		if fp.TTL > 0 {
			if e := syscall.SetsockoptInt(s, syscall.IPPROTO_IP, syscall.IP_TTL, fp.TTL); e != nil {
				sysErr = fmt.Errorf("IP_TTL: %w", e)
				return
			}
		}

		if fp.MSS > 0 {
			if e := syscall.SetsockoptInt(s, syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, fp.MSS); e != nil {
				sysErr = fmt.Errorf("TCP_MAXSEG: %w", e)
				return
			}
		}

		if fp.WindowSize > 0 {
			if e := syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_RCVBUF, fp.WindowSize/2); e != nil {
				sysErr = fmt.Errorf("SO_RCVBUF: %w", e)
				return
			}
		}

		if fp.WindowSize > 0 {
			if e := syscall.SetsockoptInt(s, syscall.IPPROTO_TCP, tcpWindowClamp, fp.WindowSize); e != nil {
				sysErr = fmt.Errorf("TCP_WINDOW_CLAMP: %w", e)
				return
			}
		}

		if fp.DFBit {
			if e := syscall.SetsockoptInt(s, syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DO); e != nil {
				sysErr = fmt.Errorf("IP_MTU_DISCOVER: %w", e)
				return
			}
		}
	})
	if err != nil {
		return err
	}
	return sysErr
}
