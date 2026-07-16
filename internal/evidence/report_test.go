package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testSourceSHA = "0123456789abcdef0123456789abcdef01234567"
	testQASHA     = "89abcdef0123456789abcdef0123456789abcdef"
	testDigest    = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func validReport() Report {
	started := time.Date(2026, 7, 16, 1, 2, 3, 0, time.UTC)
	return Report{
		SchemaVersion: 1,
		Binding: Binding{
			SourceSHA:      testSourceSHA,
			QASHA:          testQASHA,
			ArtifactSHA256: testDigest,
		},
		StartedAt:   started,
		CompletedAt: started.Add(time.Second),
		GoVersion:   "go1.22.4",
		OS:          "linux",
		Arch:        "amd64",
		Status:      "pass",
		Cases: []CaseResult{
			{Name: "artifact_identity", Status: "pass", DurationMS: 1},
		},
		Gaps: []string{},
	}
}

func TestBindingValidateRequiresCanonicalObjectIDsAndDigest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Binding)
		field  string
	}{
		{"missing source", func(b *Binding) { b.SourceSHA = "" }, "source_sha"},
		{"short source", func(b *Binding) { b.SourceSHA = strings.Repeat("a", 39) }, "source_sha"},
		{"uppercase source", func(b *Binding) { b.SourceSHA = strings.Repeat("A", 40) }, "source_sha"},
		{"nonhex source", func(b *Binding) { b.SourceSHA = strings.Repeat("g", 40) }, "source_sha"},
		{"missing QA", func(b *Binding) { b.QASHA = "" }, "qa_sha"},
		{"long QA", func(b *Binding) { b.QASHA = strings.Repeat("a", 41) }, "qa_sha"},
		{"uppercase QA", func(b *Binding) { b.QASHA = strings.Repeat("B", 40) }, "qa_sha"},
		{"short artifact", func(b *Binding) { b.ArtifactSHA256 = strings.Repeat("a", 63) }, "artifact_sha256"},
		{"uppercase artifact", func(b *Binding) { b.ArtifactSHA256 = strings.Repeat("C", 64) }, "artifact_sha256"},
		{"invalid optional head", func(b *Binding) { b.HeadSHA = "head" }, "head_sha"},
		{"invalid optional base", func(b *Binding) { b.BaseSHA = "base" }, "base_sha"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binding := validReport().Binding
			tt.mutate(&binding)
			err := binding.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("Validate() error = %v, want field %q", err, tt.field)
			}
			if strings.Contains(err.Error(), strings.Repeat("A", 40)) {
				t.Fatal("validation error disclosed rejected field value")
			}
		})
	}
}

func TestReportValidateRejectsDuplicateMissingAndNonPassRequiredCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Report)
	}{
		{"duplicate", func(r *Report) { r.Cases = append(r.Cases, r.Cases[0]) }},
		{"missing", func(r *Report) { r.Cases = nil }},
		{"failed", func(r *Report) { r.Cases[0].Status = "fail" }},
		{"skip is not a status", func(r *Report) { r.Cases[0].Status = "skip" }},
		{"negative duration", func(r *Report) { r.Cases[0].DurationMS = -1 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := validReport()
			tt.mutate(&report)
			if err := report.Validate([]string{"artifact_identity"}, nil); err == nil {
				t.Fatal("Validate() succeeded for invalid required-case state")
			}
		})
	}
}

func TestReportValidateAcceptsOptionalNotRunButRejectsRequiredNotRun(t *testing.T) {
	t.Parallel()

	report := validReport()
	report.Status = StatusFail
	report.Cases = append(report.Cases, CaseResult{Name: "optional_capability", Status: StatusNotRun})
	if err := report.Validate([]string{"artifact_identity"}, nil); err != nil {
		t.Fatalf("Validate() rejected optional not_run case: %v", err)
	}
	if err := report.Validate([]string{"artifact_identity", "optional_capability"}, nil); err == nil {
		t.Fatal("Validate() accepted required not_run case")
	}
}

func TestReportValidateEnforcesDetailClassification(t *testing.T) {
	t.Parallel()

	report := validReport()
	report.Cases[0].Detail = "auth_rejected"
	if err := report.Validate([]string{"artifact_identity"}, nil); err != nil {
		t.Fatalf("Validate() rejected valid detail classification: %v", err)
	}

	for _, detail := range []string{
		"contains space",
		"UPPERCASE",
		"contains-hyphen",
		strings.Repeat("a", 65),
	} {
		report := validReport()
		report.Cases[0].Detail = detail
		err := report.Validate([]string{"artifact_identity"}, nil)
		if err == nil {
			t.Fatalf("Validate() accepted invalid detail %q", detail)
		}
		if strings.Contains(err.Error(), detail) {
			t.Fatal("Validate() error disclosed rejected detail")
		}
	}
}

func TestReportValidateRejectsForbiddenCanaryWithoutEchoingIt(t *testing.T) {
	t.Parallel()

	for _, canary := range []string{
		"qa-master-key-canary-very-secret",
		"qa<escaped>&canary",
	} {
		report := validReport()
		report.GoVersion = "go1.22.4-" + canary
		err := report.Validate([]string{"artifact_identity"}, []string{canary})
		if err == nil {
			t.Fatal("Validate() succeeded with forbidden canary")
		}
		if strings.Contains(err.Error(), canary) {
			t.Fatal("Validate() error disclosed forbidden canary")
		}
	}
}

func TestWriteAtomicExclusiveCreatesOwnerOnlyEvidenceAndRefusesOverwrite(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "report-v1.json")
	report := validReport()
	if err := WriteAtomicExclusive(path, report, []string{"artifact_identity"}, nil); err != nil {
		t.Fatalf("WriteAtomicExclusive() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("evidence mode = %04o, want 0600", got)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	report.GoVersion = "attacker-overwrite"
	if err := WriteAtomicExclusive(path, report, []string{"artifact_identity"}, nil); err == nil {
		t.Fatal("WriteAtomicExclusive() overwrote existing evidence")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(original) {
		t.Fatal("existing evidence changed after exclusive-create failure")
	}
}

func TestWriteAtomicExclusiveRejectsOversizedSerializedReportBeforeWriting(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "oversized.json")
	report := validReport()
	report.Status = StatusFail
	report.Gaps = []string{strings.Repeat("x", maxReportSize)}

	if err := WriteAtomicExclusive(path, report, []string{"artifact_identity"}, nil); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("WriteAtomicExclusive() error = %v, want size limit rejection", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("oversized evidence became visible: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("oversized evidence created temporary files: %v", entries)
	}
}

func TestReadAndVerifyUsesExternalBindingAndStrictJSON(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "report-v1.json")
	report := validReport()
	if err := WriteAtomicExclusive(path, report, []string{"artifact_identity"}, nil); err != nil {
		t.Fatal(err)
	}

	got, err := ReadAndVerify(path, report.Binding, []string{"artifact_identity"}, nil)
	if err != nil {
		t.Fatalf("ReadAndVerify() error = %v", err)
	}
	if got.Binding != report.Binding {
		t.Fatalf("binding = %#v, want %#v", got.Binding, report.Binding)
	}

	external := report.Binding
	external.ArtifactSHA256 = strings.Repeat("f", 64)
	if _, err := ReadAndVerify(path, external, []string{"artifact_identity"}, nil); err == nil {
		t.Fatal("ReadAndVerify() trusted report's internal digest")
	}

	if err := os.WriteFile(path, append(mustRead(t, path), []byte("{}")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAndVerify(path, report.Binding, []string{"artifact_identity"}, nil); err == nil {
		t.Fatal("ReadAndVerify() accepted trailing JSON")
	}
}

func TestSHA256File(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "artifact")
	contents := []byte("exact immutable artifact")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(contents)
	want := hex.EncodeToString(sum[:])
	got, err := SHA256File(path)
	if err != nil {
		t.Fatalf("SHA256File() error = %v", err)
	}
	if got != want {
		t.Fatalf("SHA256File() = %q, want %q", got, want)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
