package transport

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"github.com/jesterfoidchopped/akamai-v3-sensor/fingerprint"
)

func BuildDialerControl(fp *fingerprint.TCPFingerprint) func(network, address string, conn syscall.RawConn) error {
	if fp == nil || fp.TTL == 0 {
		return nil
	}
	return func(network, address string, conn syscall.RawConn) error {
		return applyTCPFingerprint(conn, fp)
	}
}

func SetDialerControl(dialer *net.Dialer, fp *fingerprint.TCPFingerprint) {
	if ctrl := BuildDialerControl(fp); ctrl != nil {
		dialer.Control = ctrl
	}
}

func ApplyLocalAddrControl(dialer *net.Dialer, localAddr string) {
	if localAddr == "" {
		return
	}
	prev := dialer.Control
	dialer.Control = func(network, address string, c syscall.RawConn) error {
		applyFreebind(c)
		if prev != nil {
			return prev(network, address, c)
		}
		return nil
	}
}

func BuildLocalAddrListenControl(localAddr string) func(network, address string, c syscall.RawConn) error {
	if localAddr == "" {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		applyFreebind(c)
		return nil
	}
}

func ListenUDPWithLocalAddr(network string, localUDPAddr *net.UDPAddr, localAddr string) (*net.UDPConn, error) {
	ctrl := BuildLocalAddrListenControl(localAddr)
	if ctrl == nil {
		return net.ListenUDP(network, localUDPAddr)
	}
	lc := &net.ListenConfig{Control: ctrl}
	pc, err := lc.ListenPacket(context.Background(), network, localUDPAddr.String())
	if err != nil {
		return nil, err
	}
	udp, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, fmt.Errorf("ListenPacket returned %T, want *net.UDPConn", pc)
	}
	return udp, nil
}

func BuildDialControl(fp *fingerprint.TCPFingerprint, localAddr string) func(network, address string, c syscall.RawConn) error {
	fpCtrl := BuildDialerControl(fp)
	if fpCtrl == nil && localAddr == "" {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		if localAddr != "" {
			applyFreebind(c)
		}
		if fpCtrl != nil {
			return fpCtrl(network, address, c)
		}
		return nil
	}
}
