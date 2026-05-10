package main

/*
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    int32_t status_code;
    int32_t body_len;
    int32_t headers_len;
    int32_t protocol;  // 1=h1, 2=h2, 3=h3
    char final_url[2048];
} FastResponseMeta;

*/
import "C"
import (
	"context"
	"crypto/x509"
	"io"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/jesterfoidchopped/akamai-v3-sensor"
)

func init() {
	_ = &sensor.Request{}

	_, _ = x509.SystemCertPool()
}

//export sensor_init
func sensor_init() {
	runtime.GC()

	_, _ = x509.SystemCertPool()

	_ = make([]byte, 4096)
	runtime.GC()
}

//export sensor_warmup
func sensor_warmup(configJSON *C.char) {
	handle := sensor_session_new(configJSON)
	if handle > 0 {
		sensor_session_free(handle)
	}
}

//export sensor_warmup_full
func sensor_warmup_full(configJSON *C.char, warmupURL *C.char, warmupURLLen C.int) {
	handle := sensor_session_new(configJSON)
	if handle <= 0 {
		return
	}
	defer sensor_session_free(handle)

	if warmupURL != nil && warmupURLLen > 0 {
		rh := sensor_get_fast(handle, warmupURL, warmupURLLen)
		if rh > 0 {
			sensor_fast_free(rh)
		}
	}
}

type FastResponse struct {
	meta    *C.FastResponseMeta // C-allocated, safe to return
	body    unsafe.Pointer      // C-allocated body
	bodyLen int
	headers map[string][]string
}

var (
	fastResponses   = make(map[int64]*FastResponse)
	fastResponsesMu sync.RWMutex
	fastResponseID  int64
)

const (
	protoH1 = 1
	protoH2 = 2
	protoH3 = 3
)

func protocolToInt(p string) int32 {
	switch p {
	case "h1", "http/1.1", "HTTP/1.1":
		return protoH1
	case "h2", "http/2", "HTTP/2":
		return protoH2
	case "h3", "http/3", "HTTP/3":
		return protoH3
	default:
		return protoH2
	}
}

//export sensor_get_fast_timed
func sensor_get_fast_timed(handle C.int64_t, url *C.char, urlLen C.int, timings *C.int64_t) C.int64_t {
	t0 := time.Now()

	session := getSession(handle)
	if session == nil {
		return -1
	}

	t1 := time.Now()

	urlStr := C.GoStringN(url, urlLen)

	t2 := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req := &sensor.Request{
		Method: "GET",
		URL:    urlStr,
	}

	t3 := time.Now()

	resp, err := session.Do(ctx, req)

	t4 := time.Now()

	if err != nil {
		return -1
	}

	var bodyBytes []byte
	if resp.Body != nil {
		bodyBytes, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}

	t5 := time.Now()

	if timings != nil {
		timingsSlice := (*[5]C.int64_t)(unsafe.Pointer(timings))
		timingsSlice[0] = C.int64_t(t1.Sub(t0).Microseconds()) // getSession
		timingsSlice[1] = C.int64_t(t2.Sub(t1).Microseconds()) // string conv
		timingsSlice[2] = C.int64_t(t3.Sub(t2).Microseconds()) // ctx + req setup
		timingsSlice[3] = C.int64_t(t4.Sub(t3).Microseconds()) // session.Do
		timingsSlice[4] = C.int64_t(t5.Sub(t4).Microseconds()) // body read
	}

	return sensor_get_fast_finish(resp, bodyBytes)
}

func sensor_get_fast_finish(resp *sensor.Response, bodyBytes []byte) C.int64_t {
	meta := (*C.FastResponseMeta)(C.malloc(C.size_t(unsafe.Sizeof(C.FastResponseMeta{}))))

	meta.status_code = C.int32_t(resp.StatusCode)
	meta.body_len = C.int32_t(len(bodyBytes))
	meta.protocol = C.int32_t(protocolToInt(resp.Protocol))

	finalURLBytes := []byte(resp.FinalURL)
	if len(finalURLBytes) < 2047 {
		for i := 0; i < len(finalURLBytes); i++ {
			meta.final_url[i] = C.char(finalURLBytes[i])
		}
		meta.final_url[len(finalURLBytes)] = 0
	} else {
		meta.final_url[0] = 0
	}

	headerCount := 0
	for _, vals := range resp.Headers {
		headerCount += len(vals)
	}
	meta.headers_len = C.int32_t(headerCount)

	var cBody unsafe.Pointer
	if len(bodyBytes) > 0 {
		cBody = C.malloc(C.size_t(len(bodyBytes)))
		C.memcpy(cBody, unsafe.Pointer(&bodyBytes[0]), C.size_t(len(bodyBytes)))
	}

	fr := &FastResponse{
		meta:    meta,
		body:    cBody,
		bodyLen: len(bodyBytes),
		headers: resp.Headers,
	}

	fastResponsesMu.Lock()
	fastResponseID++
	id := fastResponseID
	fastResponses[id] = fr
	fastResponsesMu.Unlock()

	return C.int64_t(id)
}

//export sensor_get_fast
func sensor_get_fast(handle C.int64_t, url *C.char, urlLen C.int) C.int64_t {
	session := getSession(handle)
	if session == nil {
		return -1
	}

	urlStr := C.GoStringN(url, urlLen)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req := &sensor.Request{
		Method: "GET",
		URL:    urlStr,
	}

	resp, err := session.Do(ctx, req)
	if err != nil {
		return -1
	}

	var bodyBytes []byte
	if resp.Body != nil {
		bodyBytes, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}

	meta := (*C.FastResponseMeta)(C.malloc(C.size_t(unsafe.Sizeof(C.FastResponseMeta{}))))

	meta.status_code = C.int32_t(resp.StatusCode)
	meta.body_len = C.int32_t(len(bodyBytes))
	meta.protocol = C.int32_t(protocolToInt(resp.Protocol))

	finalURLBytes := []byte(resp.FinalURL)
	if len(finalURLBytes) < 2047 {
		for i := 0; i < len(finalURLBytes); i++ {
			meta.final_url[i] = C.char(finalURLBytes[i])
		}
		meta.final_url[len(finalURLBytes)] = 0
	} else {
		meta.final_url[0] = 0
	}

	headerCount := 0
	for _, vals := range resp.Headers {
		headerCount += len(vals)
	}
	meta.headers_len = C.int32_t(headerCount)

	var cBody unsafe.Pointer
	if len(bodyBytes) > 0 {
		cBody = C.malloc(C.size_t(len(bodyBytes)))
		C.memcpy(cBody, unsafe.Pointer(&bodyBytes[0]), C.size_t(len(bodyBytes)))
	}

	fr := &FastResponse{
		meta:    meta,
		body:    cBody,
		bodyLen: len(bodyBytes),
		headers: resp.Headers,
	}

	fastResponsesMu.Lock()
	fastResponseID++
	id := fastResponseID
	fastResponses[id] = fr
	fastResponsesMu.Unlock()

	return C.int64_t(id)
}

//export sensor_fast_get_meta
func sensor_fast_get_meta(handle C.int64_t) *C.FastResponseMeta {
	fastResponsesMu.RLock()
	resp, exists := fastResponses[int64(handle)]
	fastResponsesMu.RUnlock()

	if !exists || resp == nil {
		return nil
	}

	return resp.meta
}

//export sensor_fast_get_body_ptr
func sensor_fast_get_body_ptr(handle C.int64_t) unsafe.Pointer {
	fastResponsesMu.RLock()
	resp, exists := fastResponses[int64(handle)]
	fastResponsesMu.RUnlock()

	if !exists || resp == nil || resp.bodyLen == 0 {
		return nil
	}

	return resp.body
}

//export sensor_fast_get_body_len
func sensor_fast_get_body_len(handle C.int64_t) C.int {
	fastResponsesMu.RLock()
	resp, exists := fastResponses[int64(handle)]
	fastResponsesMu.RUnlock()

	if !exists || resp == nil {
		return 0
	}

	return C.int(resp.bodyLen)
}

//export sensor_fast_free
func sensor_fast_free(handle C.int64_t) {
	fastResponsesMu.Lock()
	resp, exists := fastResponses[int64(handle)]
	if exists && resp != nil {
		if resp.meta != nil {
			C.free(unsafe.Pointer(resp.meta))
		}
		if resp.body != nil {
			C.free(resp.body)
		}
		delete(fastResponses, int64(handle))
	}
	fastResponsesMu.Unlock()
}
