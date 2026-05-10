package transport

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	http "github.com/sardanioss/http"
)

var speculativeTLSBlocklist sync.Map // map[string]struct{}

func MarkProxyNoSpeculative(proxyAddr string) {
	speculativeTLSBlocklist.Store(proxyAddr, struct{}{})
}

func IsProxyNoSpeculative(proxyAddr string) bool {
	_, ok := speculativeTLSBlocklist.Load(proxyAddr)
	return ok
}

type SpeculativeTLSError struct {
	Op         string // Operation that failed: "write", "read", "parse", "status"
	StatusCode int    // HTTP status code (for status errors)
	Err        error  // Underlying error
}

func (e *SpeculativeTLSError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("speculative TLS %s: HTTP %d", e.Op, e.StatusCode)
	}
	if e.Err != nil {
		return fmt.Sprintf("speculative TLS %s: %v", e.Op, e.Err)
	}
	return fmt.Sprintf("speculative TLS %s failed", e.Op)
}

func (e *SpeculativeTLSError) Unwrap() error {
	return e.Err
}

func IsSpeculativeTLSError(err error) bool {
	var specErr *SpeculativeTLSError
	return errors.As(err, &specErr)
}

type SpeculativeConn struct {
	net.Conn
	connectRequest   string
	firstWrite       bool
	httpResponseDone bool
	readBuffer       bytes.Buffer
	headerBuffer     bytes.Buffer // Accumulates partial HTTP headers
	writeMu          sync.Mutex   // Protects firstWrite and write interception
	readMu           sync.Mutex   // Protects httpResponseDone and read interception
}

func NewSpeculativeConn(conn net.Conn, connectRequest string) *SpeculativeConn {
	return &SpeculativeConn{
		Conn:           conn,
		connectRequest: connectRequest,
	}
}

func (c *SpeculativeConn) Write(b []byte) (n int, err error) {
	c.writeMu.Lock()
	if c.firstWrite {
		c.writeMu.Unlock()
		return c.Conn.Write(b)
	}

	combined := append([]byte(c.connectRequest), b...)
	_, err = c.Conn.Write(combined)
	if err != nil {
		c.writeMu.Unlock()
		return 0, &SpeculativeTLSError{Op: "write", Err: err}
	}
	c.firstWrite = true
	c.writeMu.Unlock()
	return len(b), nil
}

func (c *SpeculativeConn) Read(b []byte) (n int, err error) {
	c.readMu.Lock()
	if c.httpResponseDone && c.readBuffer.Len() == 0 {
		c.readMu.Unlock()
		return c.Conn.Read(b)
	}

	if c.readBuffer.Len() > 0 {
		n, err = c.readBuffer.Read(b)
		c.readMu.Unlock()
		return n, err
	}

	if !c.httpResponseDone {
		n, err = c.readAndStripHTTPResponse(b)
		c.readMu.Unlock()
		return n, err
	}

	c.readMu.Unlock()
	return c.Conn.Read(b)
}

func (c *SpeculativeConn) readAndStripHTTPResponse(b []byte) (int, error) {
	for {
		tempBuf := make([]byte, 8192)
		n, err := c.Conn.Read(tempBuf)
		if err != nil {
			return 0, &SpeculativeTLSError{Op: "read", Err: err}
		}

		c.headerBuffer.Write(tempBuf[:n])
		data := c.headerBuffer.Bytes()

		headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
		if headerEnd == -1 {
			if c.headerBuffer.Len() > 16384 {
				return 0, &SpeculativeTLSError{
					Op:  "parse",
					Err: fmt.Errorf("HTTP response headers exceed 16KB limit"),
				}
			}
			continue // Loop to read more data instead of recursing
		}

		reader := bufio.NewReader(bytes.NewReader(data[:headerEnd+4]))
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			return 0, &SpeculativeTLSError{Op: "parse", Err: err}
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return 0, &SpeculativeTLSError{
				Op:         "status",
				StatusCode: resp.StatusCode,
				Err:        fmt.Errorf("%s", resp.Status),
			}
		}

		c.httpResponseDone = true
		c.headerBuffer.Reset() // Free memory

		tlsData := data[headerEnd+4:]
		if len(tlsData) > 0 {
			copied := copy(b, tlsData)
			if copied < len(tlsData) {
				c.readBuffer.Write(tlsData[copied:])
			}
			return copied, nil
		}

		return c.Conn.Read(b)
	}
}

func (c *SpeculativeConn) Close() error {
	return c.Conn.Close()
}

func (c *SpeculativeConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *SpeculativeConn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

func (c *SpeculativeConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *SpeculativeConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *SpeculativeConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}
