package client

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

type PinType int

const (
	PinTypeSHA256 PinType = iota
	PinTypeCertificate
)

type CertificatePin struct {
	Type PinType

	Hash string

	Host string

	IncludeSubdomains bool
}

type CertPinner struct {
	pins        []*CertificatePin
	allowExpiry bool // Allow expired certificates if pinned
}

func NewCertPinner() *CertPinner {
	return &CertPinner{
		pins:        make([]*CertificatePin, 0),
		allowExpiry: false,
	}
}

func (p *CertPinner) AddPin(hash string, opts ...PinOption) *CertPinner {
	pin := &CertificatePin{
		Type: PinTypeSHA256,
		Hash: normalizeHash(hash),
	}

	for _, opt := range opts {
		opt(pin)
	}

	p.pins = append(p.pins, pin)
	return p
}

func (p *CertPinner) AddPinFromCertFile(certPath string, opts ...PinOption) error {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}

	return p.AddPinFromPEM(data, opts...)
}

func (p *CertPinner) AddPinFromPEM(pemData []byte, opts ...PinOption) error {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return errors.New("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	spkiHash := CalculateSPKIHash(cert)

	pin := &CertificatePin{
		Type: PinTypeSHA256,
		Hash: spkiHash,
	}

	for _, opt := range opts {
		opt(pin)
	}

	p.pins = append(p.pins, pin)
	return nil
}

func (p *CertPinner) Verify(host string, certs []*x509.Certificate) error {
	if len(p.pins) == 0 {
		return nil // No pins configured, allow all
	}

	if len(certs) == 0 {
		return errors.New("no certificates provided")
	}

	applicablePins := p.getPinsForHost(host)
	if len(applicablePins) == 0 {
		return nil // No pins for this host
	}

	for _, cert := range certs {
		certHash := CalculateSPKIHash(cert)

		for _, pin := range applicablePins {
			if pin.Hash == certHash {
				return nil // Match found
			}
		}
	}

	return &CertPinError{
		Host:           host,
		ExpectedHashes: p.getPinHashes(applicablePins),
		ActualHashes:   getCertHashes(certs),
	}
}

func (p *CertPinner) getPinsForHost(host string) []*CertificatePin {
	var applicable []*CertificatePin

	for _, pin := range p.pins {
		if pin.Host == "" {
			applicable = append(applicable, pin)
			continue
		}

		if pin.Host == host {
			applicable = append(applicable, pin)
			continue
		}

		if pin.IncludeSubdomains && strings.HasSuffix(host, "."+pin.Host) {
			applicable = append(applicable, pin)
		}
	}

	return applicable
}

func (p *CertPinner) getPinHashes(pins []*CertificatePin) []string {
	hashes := make([]string, len(pins))
	for i, pin := range pins {
		hashes[i] = pin.Hash
	}
	return hashes
}

func getCertHashes(certs []*x509.Certificate) []string {
	hashes := make([]string, len(certs))
	for i, cert := range certs {
		hashes[i] = CalculateSPKIHash(cert)
	}
	return hashes
}

func CalculateSPKIHash(cert *x509.Certificate) string {
	spkiHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(spkiHash[:])
}

func normalizeHash(hash string) string {
	hash = strings.TrimPrefix(hash, "sha256/")
	hash = strings.TrimPrefix(hash, "sha256:")

	if len(hash) == 64 && !strings.ContainsAny(hash, "+/=") {
		decoded, err := hex.DecodeString(hash)
		if err == nil {
			return base64.StdEncoding.EncodeToString(decoded)
		}
	}

	return hash
}

type PinOption func(*CertificatePin)

func ForHost(host string) PinOption {
	return func(p *CertificatePin) {
		p.Host = host
	}
}

func IncludeSubdomains() PinOption {
	return func(p *CertificatePin) {
		p.IncludeSubdomains = true
	}
}

type CertPinError struct {
	Host           string
	ExpectedHashes []string
	ActualHashes   []string
}

func (e *CertPinError) Error() string {
	return fmt.Sprintf("certificate pinning failed for %s: expected %v, got %v",
		e.Host, e.ExpectedHashes, e.ActualHashes)
}

func (p *CertPinner) Clear() {
	p.pins = make([]*CertificatePin, 0)
}

func (p *CertPinner) HasPins() bool {
	return len(p.pins) > 0
}

func (p *CertPinner) GetPins() []*CertificatePin {
	return p.pins
}
