//go:build !linux && !darwin && !windows

package transport

import (
	"syscall"

	"github.com/jesterfoidchopped/akamai-v3-sensor/fingerprint"
)

func applyTCPFingerprint(_ syscall.RawConn, _ *fingerprint.TCPFingerprint) error {
	return nil
}
