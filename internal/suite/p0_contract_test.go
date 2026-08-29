package suite

import (
	"net/http"
	"testing"
)

func TestAcceptAuthenticatedModelsRoute(t *testing.T) {
	okBody := []byte(`{"object":"list","data":[{"id":"qa-model","object":"model"}]}`)
	tests := []struct {
		name    string
		status  int
		body    []byte
		wantErr bool
	}{
		{name: "legacy unmounted", status: http.StatusNotFound},
		{name: "p0 catalog", status: http.StatusOK, body: okBody},
		{name: "wrong object", status: http.StatusOK, body: []byte(`{"object":"error","data":[]}`), wantErr: true},
		{name: "missing permitted model", status: http.StatusOK, body: []byte(`{"object":"list","data":[{"id":"other"}]}`), wantErr: true},
		{name: "unauthorized is not an allowlisted models outcome", status: http.StatusUnauthorized, wantErr: true},
		{name: "server error", status: http.StatusInternalServerError, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := acceptAuthenticatedModelsRoute(tt.status, tt.body, "qa-model")
			if tt.wantErr && err == nil {
				t.Fatal("accepted invalid models route outcome")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("rejected valid models route outcome: %v", err)
			}
		})
	}
}

func TestAcceptJWTTPMClaim(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		hits     int
		baseline int
		wantErr  bool
	}{
		{name: "legacy reserved", status: http.StatusUnauthorized, hits: 3, baseline: 3},
		{name: "p0 preflight", status: http.StatusTooManyRequests, hits: 3, baseline: 3},
		{name: "p0 success", status: http.StatusOK, hits: 4, baseline: 3},
		{name: "reserved with egress", status: http.StatusUnauthorized, hits: 4, baseline: 3, wantErr: true},
		{name: "preflight with egress", status: http.StatusTooManyRequests, hits: 4, baseline: 3, wantErr: true},
		{name: "server error", status: http.StatusInternalServerError, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := acceptJWTTPMClaim(tt.status, tt.hits, tt.baseline)
			if tt.wantErr && err == nil {
				t.Fatal("accepted invalid TPM claim outcome")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("rejected valid TPM claim outcome: %v", err)
			}
		})
	}
}
