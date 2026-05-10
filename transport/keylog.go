package transport

import (
	"io"
	"os"
	"sync"
)

var (
	globalKeyLogWriter io.Writer
	globalKeyLogMu     sync.RWMutex
	keyLogInitialized  bool
)

func init() {
	initKeyLogFromEnv()
}

func initKeyLogFromEnv() {
	globalKeyLogMu.Lock()
	defer globalKeyLogMu.Unlock()

	if keyLogInitialized {
		return
	}
	keyLogInitialized = true

	path := os.Getenv("SSLKEYLOGFILE")
	if path == "" {
		return
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	globalKeyLogWriter = f
}

func GetKeyLogWriter() io.Writer {
	globalKeyLogMu.RLock()
	defer globalKeyLogMu.RUnlock()
	return globalKeyLogWriter
}

func SetKeyLogFile(path string) error {
	globalKeyLogMu.Lock()
	defer globalKeyLogMu.Unlock()

	if closer, ok := globalKeyLogWriter.(io.Closer); ok {
		closer.Close()
	}
	globalKeyLogWriter = nil

	if path == "" {
		return nil
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	globalKeyLogWriter = f
	return nil
}

func SetKeyLogWriter(w io.Writer) {
	globalKeyLogMu.Lock()
	defer globalKeyLogMu.Unlock()

	if closer, ok := globalKeyLogWriter.(io.Closer); ok {
		closer.Close()
	}
	globalKeyLogWriter = w
}

func NewKeyLogFileWriter(path string) (io.WriteCloser, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
}

func CloseKeyLog() error {
	globalKeyLogMu.Lock()
	defer globalKeyLogMu.Unlock()

	if closer, ok := globalKeyLogWriter.(io.Closer); ok {
		err := closer.Close()
		globalKeyLogWriter = nil
		return err
	}
	globalKeyLogWriter = nil
	return nil
}
