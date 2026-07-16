package harness

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
)

func TestProviderUsesPrivateTLS13CAAndServesQueuedResponses(t *testing.T) {
	provider, err := Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		if err := provider.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	info, err := os.Stat(provider.RootCAFile())
	if err != nil {
		t.Fatalf("stat root CA: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("root CA mode = %o, want 600", got)
	}

	rootPEM, err := os.ReadFile(provider.RootCAFile())
	if err != nil {
		t.Fatalf("read root CA: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("root CA file did not contain a certificate")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
	}}}

	header := http.Header{"X-QA-Sequence": []string{"first"}}
	body := []byte(`{"ok":true}`)
	provider.Enqueue(Response{Status: http.StatusCreated, Header: header, Body: body})
	header.Set("X-QA-Sequence", "mutated")
	body[0] = 'X'

	req, err := http.NewRequest(http.MethodPost, provider.URL()+"/v1/chat/completions?case=tls", bytes.NewBufferString("request-one"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer provider-canary")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request provider: %v", err)
	}
	responseBody, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		t.Fatalf("read response: %v", readErr)
	}
	if resp.StatusCode != http.StatusCreated || resp.Header.Get("X-QA-Sequence") != "first" || string(responseBody) != `{"ok":true}` {
		t.Fatalf("response = status %d header %q body %q", resp.StatusCode, resp.Header.Get("X-QA-Sequence"), responseBody)
	}
	if resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("TLS version = %#v, want TLS 1.3", resp.TLS)
	}
	leaf := resp.TLS.PeerCertificates[0]
	if err := leaf.VerifyHostname("localhost"); err != nil {
		t.Fatalf("leaf lacks localhost SAN: %v", err)
	}
	if err := leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("leaf lacks 127.0.0.1 SAN: %v", err)
	}

	if got := provider.HitCount(); got != 1 {
		t.Fatalf("HitCount = %d, want 1", got)
	}
	captures := provider.Snapshot()
	if len(captures) != 1 {
		t.Fatalf("len(Snapshot) = %d, want 1", len(captures))
	}
	if captures[0].Method != http.MethodPost || captures[0].Path != "/v1/chat/completions" || captures[0].RawQuery != "case=tls" || string(captures[0].Body) != "request-one" {
		t.Fatalf("unexpected capture: %#v", captures[0])
	}
	if captures[0].Header.Get("Authorization") != "Bearer provider-canary" || captures[0].TLSVersion != tls.VersionTLS13 {
		t.Fatalf("capture did not preserve headers/TLS metadata: %#v", captures[0])
	}

	// Snapshot must not grant mutable access to the provider's evidence.
	captures[0].Body[0] = 'X'
	captures[0].Header.Set("Authorization", "mutated")
	again := provider.Snapshot()
	if string(again[0].Body) != "request-one" || again[0].Header.Get("Authorization") != "Bearer provider-canary" {
		t.Fatalf("Snapshot was not defensive: %#v", again[0])
	}
}

func TestProviderRejectsTLS12(t *testing.T) {
	provider, err := Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })

	roots := x509.NewCertPool()
	rootPEM, err := os.ReadFile(provider.RootCAFile())
	if err != nil || !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatalf("load root CA: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		RootCAs:    roots,
	}}}
	if _, err := client.Get(provider.URL()); err == nil {
		t.Fatal("provider accepted TLS 1.2")
	}
}

func TestProviderQueueExhaustionFailsClosed(t *testing.T) {
	provider, err := Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })

	client := providerClient(t, provider.RootCAFile())
	resp, err := client.Get(provider.URL() + "/unexpected")
	if err != nil {
		t.Fatalf("request provider: %v", err)
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if readErr != nil {
		t.Fatalf("read response: %v", readErr)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
	if bytes.Contains(body, []byte("unexpected")) {
		t.Fatalf("failure body reflected request data: %q", body)
	}
}

func TestProviderConcurrentCapturesAndHitCount(t *testing.T) {
	provider, err := Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })

	const requests = 32
	for i := 0; i < requests; i++ {
		provider.Enqueue(Response{Status: http.StatusOK, Body: []byte("ok")})
	}
	client := providerClient(t, provider.RootCAFile())
	var wg sync.WaitGroup
	errs := make(chan error, requests)
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Post(provider.URL()+"/concurrent", "text/plain", bytes.NewBufferString("capture"))
			if err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				err = resp.Body.Close()
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent request: %v", err)
		}
	}
	if got := provider.HitCount(); got != requests {
		t.Fatalf("HitCount = %d, want %d", got, requests)
	}
	if got := len(provider.Snapshot()); got != requests {
		t.Fatalf("len(Snapshot) = %d, want %d", got, requests)
	}
}

func TestProviderCountsRejectedRequestsWithoutCapturingPartialBodies(t *testing.T) {
	provider := &Provider{}
	request := httptest.NewRequest(http.MethodPost, "https://127.0.0.1/rejected", nil)
	request.Body = io.NopCloser(errorReader{})
	recorder := httptest.NewRecorder()
	provider.handle(recorder, request)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusRequestEntityTooLarge)
	}
	if got := provider.HitCount(); got != 1 {
		t.Fatalf("HitCount = %d, want 1", got)
	}
	if captures := provider.Snapshot(); len(captures) != 0 {
		t.Fatalf("rejected partial body was captured: %#v", captures)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("synthetic read failure")
}

func providerClient(t *testing.T, rootCAFile string) *http.Client {
	t.Helper()
	rootPEM, err := os.ReadFile(rootCAFile)
	if err != nil {
		t.Fatalf("read root CA: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("append root CA")
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
	}}}
}
