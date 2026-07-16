package suite

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yknothing/AegisLLM-QA/internal/artifact"
	"github.com/yknothing/AegisLLM-QA/internal/evidence"
	"github.com/yknothing/AegisLLM-QA/internal/harness"
)

const (
	testSourceSHA = "0123456789abcdef0123456789abcdef01234567"
	testQASHA     = "89abcdef0123456789abcdef0123456789abcdef"
	testDigest    = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func TestRunRequiresEveryBaselineCaseToPass(t *testing.T) {
	called := make(map[string]int)
	cases := make([]Case, 0, len(RequiredCases()))
	for _, name := range RequiredCases() {
		name := name
		cases = append(cases, Case{Name: name, Run: func(context.Context, *Context) error {
			called[name]++
			return nil
		}})
	}

	report := Run(context.Background(), testContext(), cases)
	if report.Status != evidence.StatusPass {
		t.Fatalf("status = %q, want pass: %#v", report.Status, report.Cases)
	}
	if report.GoVersion != "go1.22.4" {
		t.Fatalf("GoVersion = %q, want inspected SUT toolchain", report.GoVersion)
	}
	if len(report.Cases) != len(RequiredCases()) {
		t.Fatalf("case count = %d, want %d", len(report.Cases), len(RequiredCases()))
	}
	for _, name := range RequiredCases() {
		if called[name] != 1 {
			t.Fatalf("case %q called %d times, want once", name, called[name])
		}
	}
}

func TestRunFailsClosedForMalformedOrIncompleteCases(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func([]Case) []Case
		wantDetail string
	}{
		{
			name: "duplicate",
			mutate: func(cases []Case) []Case {
				return append(cases, cases[0])
			},
			wantDetail: DetailDuplicateCase,
		},
		{
			name: "nil function",
			mutate: func(cases []Case) []Case {
				cases[0].Run = nil
				return cases
			},
			wantDetail: DetailNotRun,
		},
		{
			name: "missing",
			mutate: func(cases []Case) []Case {
				return cases[1:]
			},
			wantDetail: DetailNotRun,
		},
		{
			name: "panic",
			mutate: func(cases []Case) []Case {
				cases[0].Run = func(context.Context, *Context) error { panic("raw-panic-canary") }
				return cases
			},
			wantDetail: DetailPanic,
		},
		{
			name: "overflow",
			mutate: func(cases []Case) []Case {
				cases[0].Run = func(context.Context, *Context) error { return harness.ErrOutputLimit }
				return cases
			},
			wantDetail: DetailOutputOverflow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cases := passingCases()
			report := Run(context.Background(), testContext(), tt.mutate(cases))
			if report.Status != evidence.StatusFail {
				t.Fatalf("status = %q, want fail", report.Status)
			}
			if !hasDetail(report.Cases, tt.wantDetail) {
				t.Fatalf("cases = %#v, want detail %q", report.Cases, tt.wantDetail)
			}
			if tt.wantDetail == DetailNotRun && !hasStatus(report.Cases, evidence.StatusNotRun) {
				t.Fatalf("cases = %#v, want not_run status", report.Cases)
			}
			for _, result := range report.Cases {
				if strings.Contains(result.Detail, "raw-panic-canary") {
					t.Fatal("panic value leaked into report")
				}
			}
		})
	}
}

func TestRunClassifiesErrorsWithoutPersistingRawError(t *testing.T) {
	cases := passingCases()
	cases[0].Run = func(context.Context, *Context) error {
		return errors.New("raw-error-canary")
	}
	report := Run(context.Background(), testContext(), cases)
	if !hasDetail(report.Cases, DetailCaseFailed) {
		t.Fatalf("cases = %#v, want generic failure", report.Cases)
	}
	for _, result := range report.Cases {
		if strings.Contains(result.Detail, "raw-error-canary") {
			t.Fatal("raw error leaked into report")
		}
	}
}

func TestBaselineRegistersEveryRequiredCaseExactlyOnce(t *testing.T) {
	cases := Baseline()
	seen := make(map[string]int)
	for _, candidate := range cases {
		seen[candidate.Name]++
		if candidate.Run == nil {
			t.Fatalf("case %q has nil Run", candidate.Name)
		}
	}
	for _, required := range RequiredCases() {
		if seen[required] != 1 {
			t.Fatalf("required case %q registered %d times", required, seen[required])
		}
	}
	if len(cases) != len(RequiredCases()) {
		t.Fatalf("Baseline registered %d cases, want %d", len(cases), len(RequiredCases()))
	}
}

func TestValidateNetworkIsolationAllowsUnroutedKernelDevices(t *testing.T) {
	ipv4 := []byte("Iface\tDestination\tGateway\n")
	ipv6 := []byte("00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n")
	if err := validateNetworkIsolation([]string{"bonding_masters", "erspan0", "lo", "tunl0"}, ipv4, ipv6); err != nil {
		t.Fatalf("validateNetworkIsolation() error = %v", err)
	}
}

func TestValidateNetworkIsolationRejectsAnyNonLoopbackRoute(t *testing.T) {
	tests := []struct {
		name string
		ipv4 string
		ipv6 string
	}{
		{
			name: "IPv4",
			ipv4: "Iface\tDestination\tGateway\neth0\t00000000\t0100007F\n",
		},
		{
			name: "IPv6",
			ipv4: "Iface\tDestination\tGateway\n",
			ipv6: "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 00000000 eth0\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateNetworkIsolation([]string{"eth0", "lo"}, []byte(tt.ipv4), []byte(tt.ipv6)); err == nil {
				t.Fatal("validateNetworkIsolation() accepted non-loopback route")
			}
		})
	}
}

func TestWorkspaceEnvironmentDropsLANGAndRejectsNonHarnessKeys(t *testing.T) {
	environment, err := workspaceEnvironment([]string{
		"HOME=/tmp/home",
		"TMPDIR=/tmp/work",
		"PATH=/usr/bin:/bin",
		"LANG=C",
		"SSL_CERT_FILE=/tmp/ca.pem",
		harness.MasterKeyEnv + "=master",
		harness.JWTSigningKeyEnv + "=jwt",
	})
	if err != nil {
		t.Fatalf("workspaceEnvironment error = %v", err)
	}
	if _, exists := environment["LANG"]; exists {
		t.Fatal("LANG crossed into the process-harness environment map")
	}
	if environment[harness.MasterKeyEnv] != "master" || environment[harness.JWTSigningKeyEnv] != "jwt" {
		t.Fatalf("required Aegis environment missing: keys=%v", environment)
	}
	if _, err := workspaceEnvironment([]string{"LANG=C", "AWS_SECRET_ACCESS_KEY=forbidden"}); err == nil {
		t.Fatal("workspaceEnvironment accepted a non-harness key")
	}
}

func TestResignTokenProducesValidHS256SignatureOverMutatedClaims(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"kid":"vk_qa","key_source":"pool","tpm":0}`))
	token := header + "." + payload + ".ignored"
	key := "independent-qa-signing-key-32-bytes"
	got, err := resignToken(token, key, func(claims map[string]any) {
		claims["key_source"] = "byok"
		claims["byok_key_id"] = "qa-reserved"
	})
	if err != nil {
		t.Fatalf("resignToken error = %v", err)
	}
	parts := strings.Split(got, ".")
	if len(parts) != 3 || parts[0] != header {
		t.Fatalf("token structure changed unexpectedly")
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["key_source"] != "byok" || claims["byok_key_id"] != "qa-reserved" {
		t.Fatalf("claims were not mutated: %#v", claims)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		t.Fatal("signature does not authenticate the mutated payload")
	}
}

func TestRegisteredCanaryMakesEvidenceWriteFail(t *testing.T) {
	runContext := testContext()
	runContext.registerCanary([]byte("registered-secret-canary"))
	report := Run(context.Background(), runContext, passingCases())
	report.Cases[0].Detail = "registered-secret-canary"
	canaries := runContext.ForbiddenCanaries()
	defer runContext.ClearCanaries()
	if err := evidence.WriteAtomicExclusive(filepath.Join(t.TempDir(), "report.json"), report, nil, canaries); err == nil {
		t.Fatal("evidence writer accepted a registered canary")
	}
}

func passingCases() []Case {
	cases := make([]Case, 0, len(RequiredCases()))
	for _, name := range RequiredCases() {
		cases = append(cases, Case{Name: name, Run: func(context.Context, *Context) error { return nil }})
	}
	return cases
}

func testContext() *Context {
	return &Context{
		Binary: "/absolute/aegis",
		Binding: evidence.Binding{
			SourceSHA:      testSourceSHA,
			QASHA:          testQASHA,
			ArtifactSHA256: testDigest,
		},
		Identity: artifact.Identity{
			SourceSHA:      testSourceSHA,
			ArtifactSHA256: testDigest,
			Toolchain:      "go1.22.4",
		},
		StartedAt: time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC),
	}
}

func hasDetail(results []evidence.CaseResult, detail string) bool {
	for _, result := range results {
		if result.Detail == detail {
			return true
		}
	}
	return false
}

func hasStatus(results []evidence.CaseResult, status string) bool {
	for _, result := range results {
		if result.Status == status {
			return true
		}
	}
	return false
}
