package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yknothing/AegisLLM-QA/internal/evidence"
	"github.com/yknothing/AegisLLM-QA/internal/suite"
)

const (
	testSourceSHA = "0123456789abcdef0123456789abcdef01234567"
	testHeadSHA   = "123456789abcdef0123456789abcdef012345678"
	testBaseSHA   = "23456789abcdef0123456789abcdef0123456789"
	testQASHA     = "89abcdef0123456789abcdef0123456789abcdef"
	testDigest    = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func TestExecuteRejectsMissingAndUnknownCommandsWithUsageClassification(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"run"}, {"verify"}} {
		var stdout, stderr bytes.Buffer
		if code := execute(args, &stdout, &stderr); code != 2 {
			t.Fatalf("execute(%v) = %d, want 2", args, code)
		}
		if stdout.Len() != 0 || strings.TrimSpace(stderr.String()) != "qa_usage_error" {
			t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
	}
}

func TestRunRequiresWorkflowProvenanceAndMatchingEmbeddedQACommit(t *testing.T) {
	previous := qaCommit
	t.Cleanup(func() { qaCommit = previous })
	qaCommit = strings.Repeat("f", 40)

	args := []string{
		"run",
		"--sut", filepath.Join(t.TempDir(), "aegis"),
		"--source-sha", testSourceSHA,
		"--head-sha", testHeadSHA,
		"--base-sha", testBaseSHA,
		"--qa-sha", testQASHA,
		"--artifact-sha256", testDigest,
		"--workflow-run-id", "12345",
		"--evidence", filepath.Join(t.TempDir(), "report.json"),
		"--timeout", "30s",
	}
	var stdout, stderr bytes.Buffer
	if code := execute(args, &stdout, &stderr); code != 2 {
		t.Fatalf("execute = %d, want 2", code)
	}
	if stdout.Len() != 0 || strings.TrimSpace(stderr.String()) != "qa_runner_identity_invalid" {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestRunRejectsMissingHeadAndWorkflowBeforeInspectingSUT(t *testing.T) {
	previous := qaCommit
	t.Cleanup(func() { qaCommit = previous })
	qaCommit = testQASHA

	base := []string{
		"run", "--sut", filepath.Join(t.TempDir(), "missing-aegis"),
		"--source-sha", testSourceSHA, "--qa-sha", testQASHA,
		"--artifact-sha256", testDigest, "--evidence", filepath.Join(t.TempDir(), "report.json"),
		"--timeout", "30s",
	}
	for _, extra := range [][]string{{"--head-sha", testHeadSHA}, {"--workflow-run-id", "12345"}} {
		args := append(append([]string(nil), base...), extra...)
		var stdout, stderr bytes.Buffer
		if code := execute(args, &stdout, &stderr); code != 2 {
			t.Fatalf("execute(%v) = %d, want 2", extra, code)
		}
		if strings.TrimSpace(stderr.String()) != "qa_binding_invalid" {
			t.Fatalf("stderr=%q", stderr.String())
		}
	}
}

func TestVerifyRejectsExternalBindingMismatchWithoutEchoingValues(t *testing.T) {
	previous := qaCommit
	t.Cleanup(func() { qaCommit = previous })
	qaCommit = testQASHA

	dir := t.TempDir()
	evidencePath := filepath.Join(dir, "report.json")
	started := time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)
	report := evidence.Report{
		SchemaVersion: evidence.SchemaVersion,
		Binding: evidence.Binding{
			SourceSHA: testSourceSHA, HeadSHA: testHeadSHA, BaseSHA: testBaseSHA,
			QASHA: testQASHA, ArtifactSHA256: testDigest, WorkflowRunID: "12345",
		},
		StartedAt: started, CompletedAt: started.Add(time.Second), GoVersion: "go1.22.4",
		OS: "linux", Arch: "amd64", Status: evidence.StatusPass, Gaps: []string{},
	}
	for _, name := range suite.RequiredCases() {
		report.Cases = append(report.Cases, evidence.CaseResult{Name: name, Status: evidence.StatusPass, Detail: "passed"})
	}
	if err := evidence.WriteAtomicExclusive(evidencePath, report, suite.RequiredCases(), nil); err != nil {
		t.Fatal(err)
	}
	sut := filepath.Join(dir, "aegis")
	if err := os.WriteFile(sut, []byte("not-a-real-binary"), 0o700); err != nil {
		t.Fatal(err)
	}

	args := []string{
		"verify", "--sut", sut, "--evidence", evidencePath,
		"--expect-source-sha", testSourceSHA, "--expect-head-sha", testHeadSHA,
		"--expect-base-sha", strings.Repeat("f", 40), "--expect-qa-sha", testQASHA,
		"--expect-artifact-sha256", testDigest, "--expect-workflow-run-id", "12345",
	}
	var stdout, stderr bytes.Buffer
	if code := execute(args, &stdout, &stderr); code != 1 {
		t.Fatalf("execute = %d, want 1", code)
	}
	if stdout.Len() != 0 || strings.TrimSpace(stderr.String()) != "qa_evidence_invalid" {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if strings.Contains(stderr.String(), strings.Repeat("f", 40)) {
		t.Fatal("external binding value leaked")
	}
}
