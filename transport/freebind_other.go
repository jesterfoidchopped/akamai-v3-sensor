//go:build !linux

package transport

import "syscall"

func applyFreebind(_ syscall.RawConn) {}
