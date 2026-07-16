// Package harness provides hermetic black-box infrastructure for exercising an
// Aegis binary without importing or copying production source packages.
package harness

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const maxCapturedRequestBytes = 16 << 20

// Response is one queued upstream result. Enqueue makes defensive copies of
// its headers and body.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// Capture is immutable request evidence returned by Snapshot. Snapshot copies
// all byte slices and header maps before returning them.
type Capture struct {
	Method     string
	Path       string
	RawQuery   string
	Header     http.Header
	Body       []byte
	TLSVersion uint16
}

// Provider is a TLS 1.3-only, loopback test provider with FIFO responses.
type Provider struct {
	mu       sync.RWMutex
	queue    []Response
	captures []Capture
	hits     int

	server     *http.Server
	listener   net.Listener
	done       chan error
	url        string
	rootCAFile string
	tempDir    string

	closeOnce sync.Once
	closeErr  error
}

// Start creates and starts a provider with a private self-signed CA and a leaf
// certificate valid for both localhost and 127.0.0.1.
func Start() (*Provider, error) {
	tempDir, err := os.MkdirTemp("", "aegisllm-qa-provider-")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(tempDir, 0700); err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(tempDir)
		}
	}()

	certificate, caPEM, err := issueProviderCertificate()
	if err != nil {
		return nil, err
	}
	rootCAFile := filepath.Join(tempDir, "root-ca.pem")
	if err := writePrivateFile(rootCAFile, caPEM); err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	provider := &Provider{
		listener:   listener,
		done:       make(chan error, 1),
		url:        "https://" + listener.Addr().String(),
		rootCAFile: rootCAFile,
		tempDir:    tempDir,
	}
	provider.server = &http.Server{
		Handler:  http.HandlerFunc(provider.handle),
		ErrorLog: log.New(io.Discard, "", 0),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
		},
		ReadHeaderTimeout: 5 * time.Second,
	}
	tlsListener := tls.NewListener(listener, provider.server.TLSConfig)
	go func() {
		provider.done <- provider.server.Serve(tlsListener)
	}()
	cleanup = false
	return provider, nil
}

// URL returns the provider's HTTPS loopback origin.
func (p *Provider) URL() string {
	if p == nil {
		return ""
	}
	return p.url
}

// RootCAFile returns the owner-only PEM trust anchor for this provider.
func (p *Provider) RootCAFile() string {
	if p == nil {
		return ""
	}
	return p.rootCAFile
}

// Enqueue appends a response to the FIFO using defensive copies.
func (p *Provider) Enqueue(response Response) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.queue = append(p.queue, cloneResponse(response))
	p.mu.Unlock()
}

// Snapshot returns defensive copies of all captured requests.
func (p *Provider) Snapshot() []Capture {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	captures := make([]Capture, len(p.captures))
	for i := range p.captures {
		captures[i] = cloneCapture(p.captures[i])
	}
	return captures
}

// HitCount reports how many HTTP requests reached the provider handler.
func (p *Provider) HitCount() int {
	if p == nil {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.hits
}

// Close stops the provider and removes its private certificate directory. It
// is safe to call more than once.
func (p *Provider) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		shutdownErr := p.server.Shutdown(shutdownCtx)
		serveErr := <-p.done
		removeErr := os.RemoveAll(p.tempDir)
		if shutdownErr != nil {
			p.closeErr = shutdownErr
		} else if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			p.closeErr = serveErr
		} else {
			p.closeErr = removeErr
		}
	})
	return p.closeErr
}

func (p *Provider) handle(writer http.ResponseWriter, request *http.Request) {
	p.mu.Lock()
	p.hits++
	p.mu.Unlock()

	body, err := io.ReadAll(io.LimitReader(request.Body, maxCapturedRequestBytes+1))
	if err != nil || len(body) > maxCapturedRequestBytes {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusRequestEntityTooLarge)
		_, _ = io.WriteString(writer, `{"error":"request rejected"}`)
		return
	}
	capture := Capture{
		Method:   request.Method,
		Path:     request.URL.Path,
		RawQuery: request.URL.RawQuery,
		Header:   request.Header.Clone(),
		Body:     append([]byte(nil), body...),
	}
	if request.TLS != nil {
		capture.TLSVersion = request.TLS.Version
	}

	p.mu.Lock()
	p.captures = append(p.captures, capture)
	var response Response
	queued := len(p.queue) > 0
	if queued {
		response = p.queue[0]
		p.queue[0] = Response{}
		p.queue = p.queue[1:]
	}
	p.mu.Unlock()

	if !queued {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(writer, `{"error":"no queued provider response"}`)
		return
	}
	for name, values := range response.Header {
		for _, value := range values {
			writer.Header().Add(name, value)
		}
	}
	status := response.Status
	if status == 0 {
		status = http.StatusOK
	}
	writer.WriteHeader(status)
	_, _ = writer.Write(response.Body)
}

func cloneResponse(response Response) Response {
	return Response{
		Status: response.Status,
		Header: response.Header.Clone(),
		Body:   append([]byte(nil), response.Body...),
	}
}

func cloneCapture(capture Capture) Capture {
	capture.Header = capture.Header.Clone()
	capture.Body = append([]byte(nil), capture.Body...)
	return capture
}

func issueProviderCertificate() (tls.Certificate, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "AegisLLM QA Ephemeral Root"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: "AegisLLM QA Provider"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(4 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	defer clear(leafKeyDER)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER})
	defer clear(keyPEM)
	certificate, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certificate.Leaf, _ = x509.ParseCertificate(leafDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return certificate, caPEM, nil
}

func randomSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil || serial.Sign() == 0 {
		return big.NewInt(time.Now().UnixNano())
	}
	return serial
}

func writePrivateFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
