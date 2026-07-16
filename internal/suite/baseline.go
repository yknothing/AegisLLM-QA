package suite

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/yknothing/AegisLLM-QA/internal/artifact"
	"github.com/yknothing/AegisLLM-QA/internal/harness"
	"github.com/yknothing/AegisLLM-QA/internal/oracle"
)

const (
	processOutputLimit = 64 << 10
	responseBodyLimit  = 2 << 20
	caseStopTimeout    = 3 * time.Second
)

// Baseline returns the complete governed, required case set.
func Baseline() []Case {
	return []Case{
		{Name: "artifact_identity", Run: artifactIdentityCase},
		{Name: "network_namespace_isolation", Run: networkNamespaceIsolationCase},
		{Name: "operator_lifecycle", Run: operatorLifecycleCase},
		{Name: "http_unauthenticated_no_egress", Run: httpUnauthenticatedNoEgressCase},
		{Name: "http_authenticated_provider_success", Run: httpAuthenticatedProviderSuccessCase},
		{Name: "http_revoked_no_egress", Run: httpRevokedNoEgressCase},
		{Name: "http_route_and_header_contract", Run: httpRouteAndHeaderContractCase},
		{Name: "unsupported_capabilities_fail_closed", Run: unsupportedCapabilitiesFailClosedCase},
		{Name: "secret_canary_confinement", Run: secretCanaryConfinementCase},
		{Name: "process_lifecycle", Run: processLifecycleCase},
	}
}

func artifactIdentityCase(_ context.Context, runContext *Context) error {
	if runContext.Identity.SourceSHA != runContext.Binding.SourceSHA ||
		runContext.Identity.ArtifactSHA256 != runContext.Binding.ArtifactSHA256 ||
		runContext.Identity.Modified || runContext.Identity.Toolchain == "" {
		return failure("artifact_identity_mismatch")
	}
	if err := artifact.VerifyUnchanged(runContext.Binary, runContext.Identity); err != nil {
		return failure("artifact_changed")
	}
	return nil
}

func networkNamespaceIsolationCase(_ context.Context, _ *Context) error {
	if runtime.GOOS != "linux" {
		return failure("linux_required")
	}
	if os.Getpid() == 1 {
		return failure("container_init_missing")
	}
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return failure("network_inventory_unavailable")
	}
	interfaces := make([]string, 0, len(entries))
	for _, entry := range entries {
		interfaces = append(interfaces, entry.Name())
	}
	sort.Strings(interfaces)
	if len(interfaces) != 1 || interfaces[0] != "lo" {
		return failure("non_loopback_interface_present")
	}
	routes, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return failure("route_inventory_unavailable")
	}
	lines := strings.Split(strings.TrimSpace(string(routes)), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return failure("route_inventory_invalid")
		}
		if fields[0] != "lo" || fields[1] == "00000000" {
			return failure("external_route_present")
		}
	}
	return nil
}

func operatorLifecycleCase(ctx context.Context, runContext *Context) error {
	return withFixture(ctx, runContext, func(fixture *caseFixture) error {
		if err := fixture.initializeOperator(ctx); err != nil {
			return err
		}
		if err := requirePrivateRegular(fixture.workspace.RevocationFile); err != nil {
			return failure("revocation_mode_invalid")
		}
		if _, err := fixture.runOperator(ctx, []string{
			"operator", "provider-key", "import", "--config", fixture.workspace.ConfigFile,
			"--provider", harness.ProviderID,
		}, append([]byte(fixture.workspace.Canaries.ProviderKey), '\n'), false); err == nil {
			return failure("provider_key_overwrite_allowed")
		}
		originalToken, err := os.ReadFile(fixture.tokenFile)
		if err != nil {
			return failure("token_read_failed")
		}
		defer clear(originalToken)
		if _, err := fixture.runOperator(ctx, fixture.issueArgs(), nil, false); err == nil {
			return failure("token_overwrite_allowed")
		}
		after, err := os.ReadFile(fixture.tokenFile)
		if err != nil {
			return failure("token_reread_failed")
		}
		defer clear(after)
		if !bytes.Equal(originalToken, after) {
			return failure("token_changed_after_exclusive_failure")
		}
		return nil
	})
}

func httpUnauthenticatedNoEgressCase(ctx context.Context, runContext *Context) error {
	return withReadyGateway(ctx, runContext, func(fixture *caseFixture) error {
		for _, authorization := range []string{"", "Bearer invalid-qa-token"} {
			before := fixture.provider.HitCount()
			response, responseBody, err := fixture.request(ctx, http.MethodPost, "/v1/chat/completions", authorization, fixture.validRequestBody(false), nil)
			if err != nil {
				return err
			}
			if response.StatusCode != http.StatusUnauthorized {
				return failure("unauthenticated_status_invalid")
			}
			if fixture.provider.HitCount() != before {
				return failure("unauthenticated_provider_egress")
			}
			if len(fixture.workspace.Oracle.ScanBytes(oracle.SurfaceGatewayResponse, responseBody)) != 0 {
				return failure("unauthenticated_response_canary")
			}
		}
		return nil
	})
}

func httpAuthenticatedProviderSuccessCase(ctx context.Context, runContext *Context) error {
	return withReadyGateway(ctx, runContext, func(fixture *caseFixture) error {
		return fixture.assertAuthenticatedSuccess(ctx, true)
	})
}

func httpRevokedNoEgressCase(ctx context.Context, runContext *Context) error {
	return withReadyGateway(ctx, runContext, func(fixture *caseFixture) error {
		if _, err := fixture.runOperator(ctx, []string{
			"operator", "virtual-key", "revoke", "--config", fixture.workspace.ConfigFile, "--kid", fixture.keyID,
		}, nil, true); err != nil {
			return err
		}
		baselineHits := fixture.provider.HitCount()
		deadline := time.Now().Add(2 * time.Second)
		sawBadRequest := false
		for {
			response, body, err := fixture.request(ctx, http.MethodPost, "/v1/chat/completions", "Bearer "+fixture.token, []byte(`{"model":`), nil)
			if err != nil {
				return err
			}
			if len(fixture.workspace.Oracle.ScanBytes(oracle.SurfaceGatewayResponse, body)) != 0 {
				return failure("revocation_response_canary")
			}
			switch response.StatusCode {
			case http.StatusBadRequest:
				sawBadRequest = true
			case http.StatusUnauthorized:
				if !sawBadRequest {
					return failure("revocation_transition_not_observed")
				}
				if fixture.provider.HitCount() != baselineHits {
					return failure("revoked_poll_provider_egress")
				}
				response, body, err = fixture.request(ctx, http.MethodPost, "/v1/chat/completions", "Bearer "+fixture.token, fixture.validRequestBody(false), nil)
				if err != nil {
					return err
				}
				if response.StatusCode != http.StatusUnauthorized || fixture.provider.HitCount() != baselineHits {
					return failure("revoked_valid_request_allowed")
				}
				if len(fixture.workspace.Oracle.ScanBytes(oracle.SurfaceGatewayResponse, body)) != 0 {
					return failure("revoked_valid_response_canary")
				}
				return nil
			default:
				return failure("revocation_poll_status_invalid")
			}
			if time.Now().After(deadline) {
				return failure("revocation_deadline")
			}
			select {
			case <-ctx.Done():
				return failure("case_deadline")
			case <-time.After(10 * time.Millisecond):
			}
		}
	})
}

func httpRouteAndHeaderContractCase(ctx context.Context, runContext *Context) error {
	return withReadyGateway(ctx, runContext, func(fixture *caseFixture) error {
		matrix := []struct {
			method string
			path   string
			status int
		}{
			{http.MethodPost, "/health", http.StatusMethodNotAllowed},
			{http.MethodGet, "/v1/chat/completions", http.StatusMethodNotAllowed},
			{http.MethodPut, "/v1/chat/completions", http.StatusMethodNotAllowed},
			{http.MethodDelete, "/v1/chat/completions", http.StatusMethodNotAllowed},
			{http.MethodGet, "/", http.StatusNotFound},
			{http.MethodGet, "/metrics", http.StatusNotFound},
			{http.MethodGet, "/debug/pprof", http.StatusNotFound},
			{http.MethodGet, "/v1/models", http.StatusNotFound},
			{http.MethodGet, "/admin/health", http.StatusNotFound},
			{http.MethodPost, "/admin/keys/virtual", http.StatusNotFound},
			{http.MethodDelete, "/admin/keys/virtual/qa", http.StatusNotFound},
			{http.MethodPost, "/admin/keys/byok", http.StatusNotFound},
		}
		baselineHits := fixture.provider.HitCount()
		for _, entry := range matrix {
			response, body, err := fixture.request(ctx, entry.method, entry.path, "Bearer "+fixture.token, nil, nil)
			if err != nil {
				return err
			}
			if response.StatusCode != entry.status {
				return failure("route_matrix_status_invalid")
			}
			if len(fixture.workspace.Oracle.ScanBytes(oracle.SurfaceGatewayResponse, body)) != 0 {
				return failure("route_matrix_response_canary")
			}
		}
		if fixture.provider.HitCount() != baselineHits {
			return failure("route_matrix_provider_egress")
		}
		return fixture.assertAuthenticatedSuccess(ctx, false)
	})
}

func unsupportedCapabilitiesFailClosedCase(ctx context.Context, runContext *Context) error {
	return withFixture(ctx, runContext, func(fixture *caseFixture) error {
		if err := fixture.initializeOperator(ctx); err != nil {
			return err
		}
		base, err := os.ReadFile(fixture.workspace.ConfigFile)
		if err != nil {
			return failure("config_read_failed")
		}
		defer clear(base)
		variants := []func(map[string]any){
			func(cfg map[string]any) { cfg["kms"].(map[string]any)["vault"] = map[string]any{} },
			func(cfg map[string]any) { cfg["rate_limit"].(map[string]any)["backend"] = "redis" },
			func(cfg map[string]any) { cfg["quota"].(map[string]any)["enabled"] = true },
			func(cfg map[string]any) { cfg["providers"].([]any)[0].(map[string]any)["max_tpm"] = float64(1) },
			func(cfg map[string]any) { cfg["providers"].([]any)[0].(map[string]any)["type"] = "reserved-adapter" },
		}
		for _, mutate := range variants {
			var cfg map[string]any
			if err := json.Unmarshal(base, &cfg); err != nil {
				return failure("config_decode_failed")
			}
			mutate(cfg)
			encoded, err := json.Marshal(cfg)
			if err != nil {
				return failure("config_encode_failed")
			}
			if err := os.WriteFile(fixture.workspace.ConfigFile, encoded, 0o600); err != nil {
				return failure("config_variant_write_failed")
			}
			variantCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			result, runErr := harness.Run(variantCtx, runContext.Binary, []string{"-config", fixture.workspace.ConfigFile}, nil, fixture.environment, processOutputLimit)
			cancel()
			scanErr := scanCommandResult(fixture.workspace.Oracle, result)
			if errors.Is(scanErr, harness.ErrOutputLimit) {
				return harness.ErrOutputLimit
			}
			if scanErr != nil {
				return failure("unsupported_output_canary")
			}
			if errors.Is(runErr, harness.ErrProcessTimeout) {
				return failure("unsupported_capability_started")
			}
			if runErr == nil || result.ExitCode == 0 {
				return failure("unsupported_capability_started")
			}
			if errors.Is(runErr, harness.ErrOutputLimit) {
				return harness.ErrOutputLimit
			}
		}
		if fixture.provider.HitCount() != 0 {
			return failure("unsupported_capability_provider_egress")
		}
		if err := os.WriteFile(fixture.workspace.ConfigFile, base, 0o600); err != nil {
			return failure("config_restore_failed")
		}
		gateway, err := harness.StartGateway(ctx, runContext.Binary, fixture.workspace.ConfigFile, fixture.environment, processOutputLimit)
		if err != nil {
			return failure("gateway_start_failed")
		}
		fixture.gateway = gateway
		healthCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if err := gateway.WaitHealthy(healthCtx, fixture.workspace.GatewayURL+"/health"); err != nil {
			return failure("gateway_health_failed")
		}
		claimVariants := []func(map[string]any){
			func(claims map[string]any) {
				claims["key_source"] = "byok"
				claims["byok_key_id"] = "qa-reserved-byok"
			},
			func(claims map[string]any) { claims["tpm"] = float64(1) },
		}
		baselineHits := fixture.provider.HitCount()
		for _, mutate := range claimVariants {
			forged, err := resignToken(fixture.token, fixture.workspace.Canaries.JWTSigningKey, mutate)
			if err != nil {
				return err
			}
			if err := fixture.workspace.Oracle.RegisterVirtualToken([]byte(forged)); err != nil {
				return failure("token_oracle_registration_failed")
			}
			fixture.runContext.registerCanary([]byte(forged))
			response, body, err := fixture.request(ctx, http.MethodPost, "/v1/chat/completions", "Bearer "+forged, fixture.validRequestBody(false), nil)
			forged = ""
			if err != nil {
				return err
			}
			if response.StatusCode != http.StatusUnauthorized || fixture.provider.HitCount() != baselineHits {
				return failure("unsupported_claim_allowed")
			}
			if len(fixture.workspace.Oracle.ScanBytes(oracle.SurfaceGatewayResponse, body)) != 0 {
				return failure("unsupported_claim_response_canary")
			}
		}
		return nil
	})
}

func secretCanaryConfinementCase(ctx context.Context, runContext *Context) error {
	return withReadyGateway(ctx, runContext, func(fixture *caseFixture) error {
		probe := []byte(fixture.workspace.Canaries.Error)
		if len(fixture.workspace.Oracle.ScanBytes(oracle.SurfaceGatewayResponse, probe)) == 0 {
			return failure("gateway_error_default_allowlist_too_broad")
		}
		if err := fixture.workspace.Oracle.Allow(oracle.SurfaceGatewayResponse, oracle.LabelError); err != nil {
			return failure("oracle_allow_failed")
		}
		if len(fixture.workspace.Oracle.ScanBytes(oracle.SurfaceGatewayResponse, probe)) != 0 {
			return failure("gateway_error_allowlist_failed")
		}
		providerBody := []byte(`{"error":{"message":"` + fixture.workspace.Canaries.Error + `"}}`)
		if len(fixture.workspace.Oracle.ScanBytes(oracle.SurfaceProviderResponse, providerBody)) != 0 {
			return failure("provider_response_oracle_invalid")
		}
		fixture.provider.Enqueue(harness.Response{
			Status: http.StatusInternalServerError,
			Header: http.Header{"Content-Type": []string{"application/json"}},
			Body:   providerBody,
		})
		response, body, err := fixture.request(ctx, http.MethodPost, "/v1/chat/completions", "Bearer "+fixture.token, fixture.validRequestBody(false), nil)
		if err != nil {
			return err
		}
		if response.StatusCode != http.StatusInternalServerError || !bytes.Equal(body, providerBody) {
			return failure("provider_error_contract_invalid")
		}
		if len(fixture.workspace.Oracle.ScanBytes(oracle.SurfaceGatewayResponse, body)) != 0 {
			return failure("provider_error_oracle_invalid")
		}
		return nil
	})
}

func processLifecycleCase(ctx context.Context, runContext *Context) error {
	return withReadyGateway(ctx, runContext, func(fixture *caseFixture) error {
		stopCtx, cancel := context.WithTimeout(context.Background(), caseStopTimeout)
		defer cancel()
		if err := fixture.gateway.Stop(stopCtx); err != nil {
			return failure("gateway_stop_failed")
		}
		stdout, stderr, truncated := fixture.gateway.Logs()
		if truncated {
			return harness.ErrOutputLimit
		}
		if len(fixture.workspace.Oracle.ScanBytes(oracle.SurfaceStdout, []byte(stdout))) != 0 ||
			len(fixture.workspace.Oracle.ScanBytes(oracle.SurfaceStderr, []byte(stderr))) != 0 {
			return failure("gateway_log_canary")
		}
		fixture.gateway = nil
		return nil
	})
}

type caseFixture struct {
	runContext  *Context
	provider    *harness.Provider
	workspace   *harness.Workspace
	gateway     *harness.Gateway
	environment map[string]string
	tokenFile   string
	token       string
	keyID       string
}

func withFixture(ctx context.Context, runContext *Context, run func(*caseFixture) error) (err error) {
	fixture, err := newCaseFixture(runContext)
	if err != nil {
		return err
	}
	defer func() {
		if cleanupErr := fixture.scanAndCleanup(); cleanupErr != nil && err == nil {
			err = cleanupErr
		}
	}()
	return run(fixture)
}

func withReadyGateway(ctx context.Context, runContext *Context, run func(*caseFixture) error) error {
	return withFixture(ctx, runContext, func(fixture *caseFixture) error {
		if err := fixture.initializeOperator(ctx); err != nil {
			return err
		}
		gateway, err := harness.StartGateway(ctx, runContext.Binary, fixture.workspace.ConfigFile, fixture.environment, processOutputLimit)
		if err != nil {
			return failure("gateway_start_failed")
		}
		fixture.gateway = gateway
		healthCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if err := gateway.WaitHealthy(healthCtx, fixture.workspace.GatewayURL+"/health"); err != nil {
			if errors.Is(err, harness.ErrOutputLimit) {
				return harness.ErrOutputLimit
			}
			return failure("gateway_health_failed")
		}
		return run(fixture)
	})
}

func newCaseFixture(runContext *Context) (*caseFixture, error) {
	if runContext == nil || !filepath.IsAbs(runContext.Binary) {
		return nil, failure("run_context_invalid")
	}
	provider, err := harness.Start()
	if err != nil {
		return nil, failure("provider_start_failed")
	}
	workspace, err := harness.New(provider.URL(), provider.RootCAFile())
	if err != nil {
		_ = provider.Close()
		return nil, failure("workspace_create_failed")
	}
	environment, err := workspaceEnvironment(workspace.Environment())
	if err != nil {
		_ = workspace.Close()
		_ = provider.Close()
		return nil, err
	}
	for _, value := range []string{
		workspace.Canaries.MasterKey,
		workspace.Canaries.JWTSigningKey,
		workspace.Canaries.ProviderKey,
		workspace.Canaries.Prompt,
		workspace.Canaries.Completion,
		workspace.Canaries.Error,
	} {
		copyValue := []byte(value)
		runContext.registerCanary(copyValue)
		clear(copyValue)
	}
	return &caseFixture{
		runContext:  runContext,
		provider:    provider,
		workspace:   workspace,
		environment: environment,
		tokenFile:   filepath.Join(workspace.RootDir, "virtual-key.jwt"),
	}, nil
}

func workspaceEnvironment(environment []string) (map[string]string, error) {
	allowed := map[string]struct{}{
		"PATH": {}, "HOME": {}, "TMPDIR": {}, "SSL_CERT_FILE": {}, "SSL_CERT_DIR": {},
		harness.MasterKeyEnv: {}, harness.JWTSigningKeyEnv: {},
	}
	result := make(map[string]string, len(environment))
	for _, item := range environment {
		name, value, ok := strings.Cut(item, "=")
		if !ok || name == "" {
			return nil, failure("workspace_environment_invalid")
		}
		if name == "LANG" {
			continue
		}
		if _, ok := allowed[name]; !ok {
			return nil, failure("workspace_environment_disallowed")
		}
		if _, duplicate := result[name]; duplicate {
			return nil, failure("workspace_environment_duplicate")
		}
		result[name] = value
	}
	return result, nil
}

func (fixture *caseFixture) initializeOperator(ctx context.Context) error {
	if err := os.Remove(fixture.workspace.RevocationFile); err != nil {
		return failure("revocation_prebuilt_remove_failed")
	}
	if _, err := fixture.runOperator(ctx, []string{
		"operator", "revocation", "init", "--config", fixture.workspace.ConfigFile,
	}, nil, true); err != nil {
		return err
	}
	if _, err := fixture.runOperator(ctx, []string{
		"operator", "provider-key", "import", "--config", fixture.workspace.ConfigFile,
		"--provider", harness.ProviderID,
	}, append([]byte(fixture.workspace.Canaries.ProviderKey), '\n'), true); err != nil {
		return err
	}
	if _, err := fixture.runOperator(ctx, fixture.issueArgs(), nil, true); err != nil {
		return err
	}
	token, err := os.ReadFile(fixture.tokenFile)
	if err != nil {
		return failure("token_read_failed")
	}
	defer clear(token)
	trimmed := bytes.TrimSpace(token)
	if len(trimmed) == 0 {
		return failure("token_file_invalid")
	}
	if err := fixture.workspace.Oracle.RegisterVirtualToken(trimmed); err != nil {
		return failure("token_oracle_registration_failed")
	}
	fixture.runContext.registerCanary(trimmed)
	if bytes.ContainsAny(trimmed, "\r\n") {
		return failure("token_file_invalid")
	}
	fixture.token = string(trimmed)
	fixture.keyID, err = tokenKeyID(fixture.token)
	if err != nil {
		return err
	}
	return requirePrivateRegular(fixture.tokenFile)
}

func (fixture *caseFixture) issueArgs() []string {
	return []string{
		"operator", "virtual-key", "issue", "--config", fixture.workspace.ConfigFile,
		"--subject", "independent-qa", "--models", harness.Model, "--ttl", "30m",
		"--rpm", "60", "--max-concurrency", "4", "--out", fixture.tokenFile,
	}
}

func (fixture *caseFixture) runOperator(ctx context.Context, args []string, stdin []byte, expectSuccess bool) (harness.CommandResult, error) {
	defer clear(stdin)
	result, err := harness.Run(ctx, fixture.runContext.Binary, args, stdin, fixture.environment, processOutputLimit)
	scanErr := scanCommandResult(fixture.workspace.Oracle, result)
	if errors.Is(scanErr, harness.ErrOutputLimit) {
		return result, harness.ErrOutputLimit
	}
	if scanErr != nil {
		return result, failure("operator_output_canary")
	}
	if errors.Is(err, harness.ErrOutputLimit) || result.Truncated {
		return result, harness.ErrOutputLimit
	}
	if expectSuccess && err != nil {
		return result, failure("operator_command_failed")
	}
	if !expectSuccess && err == nil {
		return result, failure("operator_command_unexpected_success")
	}
	return result, err
}

func (fixture *caseFixture) validRequestBody(withPII bool) []byte {
	content := fixture.workspace.Canaries.Prompt
	if withPII {
		content += " alice@example.com"
	}
	body, _ := json.Marshal(map[string]any{
		"model":    harness.Model,
		"messages": []map[string]string{{"role": "user", "content": content}},
	})
	return body
}

func (fixture *caseFixture) assertAuthenticatedSuccess(ctx context.Context, withPII bool) error {
	responseBody, _ := json.Marshal(map[string]any{
		"id":      "qa-completion",
		"choices": []map[string]any{{"message": map[string]string{"role": "assistant", "content": fixture.workspace.Canaries.Completion}}},
	})
	defer clear(responseBody)
	fixture.provider.Enqueue(harness.Response{
		Status: http.StatusOK,
		Header: http.Header{
			"Content-Type":       []string{"application/json"},
			"X-Request-Id":       []string{"provider-qa-request"},
			"Set-Cookie":         []string{"provider-session=forbidden"},
			"Proxy-Authenticate": []string{"Basic forbidden"},
			"X-Provider-Account": []string{"forbidden-account"},
		},
		Body: responseBody,
	})
	headers := http.Header{
		"X-Api-Key":           []string{"client-api-key-forbidden"},
		"Proxy-Authorization": []string{"Bearer client-proxy-forbidden"},
		"Cookie":              []string{"client-session=forbidden"},
		"X-Provider-Account":  []string{"client-account-forbidden"},
	}
	response, body, err := fixture.request(ctx, http.MethodPost, "/v1/chat/completions", "Bearer "+fixture.token, fixture.validRequestBody(withPII), headers)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK || !bytes.Equal(body, responseBody) {
		return failure("authenticated_response_invalid")
	}
	if response.Header.Get("X-Upstream-Request-Id") != "provider-qa-request" {
		return failure("upstream_request_id_contract_invalid")
	}
	for _, name := range []string{"Set-Cookie", "Proxy-Authenticate", "X-Provider-Account", "Authorization"} {
		if response.Header.Get(name) != "" {
			return failure("unsafe_provider_header_returned")
		}
	}
	if len(fixture.workspace.Oracle.ScanBytes(oracle.SurfaceGatewayResponse, body)) != 0 {
		return failure("success_response_canary_invalid")
	}
	captures := fixture.provider.Snapshot()
	if len(captures) != 1 {
		return failure("provider_capture_count_invalid")
	}
	capture := captures[0]
	if capture.Method != http.MethodPost || capture.Path != "/v1/chat/completions" || capture.TLSVersion != tls.VersionTLS13 {
		return failure("provider_transport_contract_invalid")
	}
	if capture.Header.Get("Authorization") != "Bearer "+fixture.workspace.Canaries.ProviderKey {
		return failure("provider_credential_contract_invalid")
	}
	for _, name := range []string{"X-Api-Key", "Proxy-Authorization", "Cookie", "X-Provider-Account"} {
		if capture.Header.Get(name) != "" {
			return failure("unsafe_client_header_forwarded")
		}
	}
	if !bytes.Contains(capture.Body, []byte(fixture.workspace.Canaries.Prompt)) {
		return failure("provider_prompt_missing")
	}
	if withPII && (bytes.Contains(capture.Body, []byte("alice@example.com")) || !bytes.Contains(capture.Body, []byte("[EMAIL_REDACTED]"))) {
		return failure("provider_pii_not_redacted")
	}
	return nil
}

func (fixture *caseFixture) request(ctx context.Context, method, path, authorization string, body []byte, headers http.Header) (*http.Response, []byte, error) {
	defer clear(body)
	request, err := http.NewRequestWithContext(ctx, method, fixture.workspace.GatewayURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, nil, failure("client_request_create_failed")
	}
	request.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	defer transport.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return nil, nil, failure("client_request_failed")
	}
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, responseBodyLimit+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		return nil, nil, failure("client_response_read_failed")
	}
	if len(responseBody) > responseBodyLimit {
		return nil, nil, harness.ErrOutputLimit
	}
	return response, responseBody, nil
}

func (fixture *caseFixture) scanAndCleanup() error {
	var cleanupError error
	if fixture.gateway != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), caseStopTimeout)
		stopErr := fixture.gateway.Stop(stopCtx)
		cancel()
		if stopErr != nil {
			cleanupError = failure("gateway_cleanup_failed")
		}
		stdout, stderr, truncated := fixture.gateway.Logs()
		if truncated {
			cleanupError = harness.ErrOutputLimit
		}
		if len(fixture.workspace.Oracle.ScanBytes(oracle.SurfaceStdout, []byte(stdout))) != 0 ||
			len(fixture.workspace.Oracle.ScanBytes(oracle.SurfaceStderr, []byte(stderr))) != 0 {
			cleanupError = failure("gateway_log_canary")
		}
	}
	if fixture.tokenFile != "" {
		if token, err := os.ReadFile(fixture.tokenFile); err == nil {
			if len(fixture.workspace.Oracle.ScanBytes(oracle.SurfaceTokenFile, token)) != 0 {
				cleanupError = failure("token_file_canary_invalid")
			}
			clear(token)
			if err := os.Remove(fixture.tokenFile); err != nil {
				cleanupError = failure("token_cleanup_failed")
			}
		} else if !os.IsNotExist(err) {
			cleanupError = failure("token_cleanup_read_failed")
		}
	}
	fixture.token = ""
	if config, err := os.ReadFile(fixture.workspace.ConfigFile); err == nil {
		if len(fixture.workspace.Oracle.ScanBytes(oracle.SurfaceConfigFile, config)) != 0 {
			cleanupError = failure("config_canary")
		}
	}
	environment := fixture.workspace.Environment()
	if len(fixture.workspace.Oracle.ScanBytes(oracle.SurfaceProcessEnvironment, []byte(strings.Join(environment, "\n")))) != 0 {
		cleanupError = failure("environment_canary")
	}
	for _, capture := range fixture.provider.Snapshot() {
		serializedHeader, _ := json.Marshal(capture.Header)
		observed := bytes.Join([][]byte{[]byte(capture.Method), []byte(capture.Path), []byte(capture.RawQuery), serializedHeader, capture.Body}, []byte{'\n'})
		if len(fixture.workspace.Oracle.ScanBytes(oracle.SurfaceProviderRequest, observed)) != 0 {
			cleanupError = failure("provider_capture_canary")
		}
		clear(serializedHeader)
		clear(observed)
	}
	if findings, err := fixture.workspace.Oracle.ScanTree(oracle.SurfaceFileTree, fixture.workspace.RootDir); err != nil || len(findings) != 0 {
		cleanupError = failure("workspace_tree_canary")
	}
	if err := fixture.provider.Close(); err != nil && cleanupError == nil {
		cleanupError = failure("provider_cleanup_failed")
	}
	if err := fixture.workspace.Close(); err != nil && cleanupError == nil {
		cleanupError = failure("workspace_cleanup_failed")
	}
	return cleanupError
}

func scanCommandResult(set *oracle.Set, result harness.CommandResult) error {
	if result.Truncated {
		return harness.ErrOutputLimit
	}
	if len(set.ScanBytes(oracle.SurfaceStdout, []byte(result.Stdout))) != 0 || len(set.ScanBytes(oracle.SurfaceStderr, []byte(result.Stderr))) != 0 {
		return failure("process_output_canary")
	}
	return nil
}

func tokenKeyID(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", failure("token_format_invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", failure("token_payload_invalid")
	}
	defer clear(payload)
	var claims struct {
		KeyID string `json:"kid"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || strings.TrimSpace(claims.KeyID) == "" {
		return "", failure("token_claims_invalid")
	}
	return claims.KeyID, nil
}

// resignToken is a QA-owned adversarial helper. It preserves the original
// JOSE header, mutates only decoded claims, and authenticates the new payload
// with the fixture's synthetic HS256 key.
func resignToken(token, signingKey string, mutate func(map[string]any)) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || mutate == nil || len(signingKey) < 32 {
		return "", failure("token_resign_input_invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", failure("token_resign_payload_invalid")
	}
	defer clear(payload)
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", failure("token_resign_claims_invalid")
	}
	mutate(claims)
	mutated, err := json.Marshal(claims)
	if err != nil {
		return "", failure("token_resign_encode_failed")
	}
	defer clear(mutated)
	payloadSegment := base64.RawURLEncoding.EncodeToString(mutated)
	signingInput := parts[0] + "." + payloadSegment
	key := []byte(signingKey)
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(signingInput))
	signature := mac.Sum(nil)
	defer clear(signature)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func requirePrivateRegular(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return failure("private_file_invalid")
	}
	return nil
}
