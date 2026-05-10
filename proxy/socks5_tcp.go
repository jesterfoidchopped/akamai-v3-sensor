package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"syscall"
	"time"
)

type SOCKS5Dialer struct {
	proxyHost string
	proxyPort string

	username string
	password string

	timeout time.Duration

	localAddr string

	Control func(network, address string, conn syscall.RawConn) error
}

func NewSOCKS5Dialer(proxyURL string) (*SOCKS5Dialer, error) {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	if parsed.Scheme != "socks5" && parsed.Scheme != "socks5h" {
		return nil, fmt.Errorf("unsupported proxy scheme: %s (need socks5 or socks5h)", parsed.Scheme)
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "1080" // Default SOCKS5 port
	}

	dialer := &SOCKS5Dialer{
		proxyHost: host,
		proxyPort: port,
		timeout:   30 * time.Second,
	}

	if parsed.User != nil {
		dialer.username = parsed.User.Username()
		dialer.password, _ = parsed.User.Password()
	}

	return dialer, nil
}

func (d *SOCKS5Dialer) SetLocalAddr(addr string) {
	d.localAddr = addr
}

func (d *SOCKS5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	targetHost, targetPort, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid target address: %w", err)
	}

	resolver := &net.Resolver{PreferGo: false}
	proxyIPs, err := resolver.LookupHost(ctx, d.proxyHost)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve proxy host %s: %w", d.proxyHost, err)
	}
	if len(proxyIPs) == 0 {
		return nil, fmt.Errorf("no IP addresses found for proxy host %s", d.proxyHost)
	}

	proxyAddr := net.JoinHostPort(proxyIPs[0], d.proxyPort)
	dialer := &net.Dialer{Timeout: d.timeout}
	if d.localAddr != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(d.localAddr)}
	}
	if d.Control != nil {
		dialer.Control = d.Control
	}
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SOCKS5 proxy: %w", err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	if err := d.socks5Handshake(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 handshake failed: %w", err)
	}

	if err := d.socks5Connect(conn, targetHost, targetPort); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 CONNECT failed: %w", err)
	}

	conn.SetDeadline(time.Time{})

	return conn, nil
}

func (d *SOCKS5Dialer) socks5Handshake(conn net.Conn) error {
	var greeting []byte
	if d.username != "" {
		greeting = []byte{socks5Version, 0x02, authNone, authPassword}
	} else {
		greeting = []byte{socks5Version, 0x01, authNone}
	}

	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("failed to send greeting: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if resp[0] != socks5Version {
		return fmt.Errorf("invalid SOCKS version: %d", resp[0])
	}

	switch resp[1] {
	case authNone:
		return nil
	case authPassword:
		return d.socks5PasswordAuth(conn)
	case authNoAccept:
		return errors.New("proxy rejected all authentication methods")
	default:
		return fmt.Errorf("unsupported authentication method: %d", resp[1])
	}
}

func (d *SOCKS5Dialer) socks5PasswordAuth(conn net.Conn) error {
	if d.username == "" {
		return errors.New("proxy requires authentication but no credentials provided")
	}

	authReq := make([]byte, 0, 3+len(d.username)+len(d.password))
	authReq = append(authReq, 0x01) // Auth sub-negotiation version
	authReq = append(authReq, byte(len(d.username)))
	authReq = append(authReq, []byte(d.username)...)
	authReq = append(authReq, byte(len(d.password)))
	authReq = append(authReq, []byte(d.password)...)

	if _, err := conn.Write(authReq); err != nil {
		return fmt.Errorf("failed to send auth request: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if resp[1] != 0x00 {
		return errors.New("authentication failed: invalid credentials")
	}

	return nil
}

func (d *SOCKS5Dialer) socks5Connect(conn net.Conn, host, port string) error {
	portNum, err := net.LookupPort("tcp", port)
	if err != nil {
		return fmt.Errorf("invalid port: %w", err)
	}

	request := []byte{socks5Version, cmdConnect, 0x00}

	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			request = append(request, atypIPv4)
			request = append(request, ip4...)
		} else {
			request = append(request, atypIPv6)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("domain name too long")
		}
		request = append(request, atypDomain)
		request = append(request, byte(len(host)))
		request = append(request, []byte(host)...)
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(portNum))
	request = append(request, portBytes...)

	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("failed to send CONNECT request: %w", err)
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("failed to read reply header: %w", err)
	}

	if header[0] != socks5Version {
		return fmt.Errorf("invalid SOCKS version in reply: %d", header[0])
	}

	if header[1] != replySuccess {
		return fmt.Errorf("CONNECT failed: %s (reply=%d)", socks5ReplyString(header[1]), header[1])
	}

	switch header[3] {
	case atypIPv4:
		if _, err := io.ReadFull(conn, make([]byte, 6)); err != nil {
			return fmt.Errorf("failed to read bound address: %w", err)
		}
	case atypDomain:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return fmt.Errorf("failed to read domain length: %w", err)
		}
		if _, err := io.ReadFull(conn, make([]byte, int(lenByte[0])+2)); err != nil {
			return fmt.Errorf("failed to read domain and port: %w", err)
		}
	case atypIPv6:
		if _, err := io.ReadFull(conn, make([]byte, 18)); err != nil {
			return fmt.Errorf("failed to read bound address: %w", err)
		}
	default:
		return fmt.Errorf("unsupported address type in reply: %d", header[3])
	}

	return nil
}

func IsSOCKS5URL(proxyURL string) bool {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return false
	}
	return parsed.Scheme == "socks5" || parsed.Scheme == "socks5h"
}
