// Package evidence validates and persists sanitized, revision-bound QA reports.
package evidence

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	SchemaVersion = 1
	StatusPass    = "pass"
	StatusFail    = "fail"
	StatusNotRun  = "not_run"
	maxReportSize = 1 << 20
)

var detailClassification = regexp.MustCompile(`\A[a-z0-9_]{1,64}\z`)

// Binding identifies every independently controlled input to a QA result.
type Binding struct {
	SourceSHA      string `json:"source_sha"`
	HeadSHA        string `json:"head_sha,omitempty"`
	BaseSHA        string `json:"base_sha,omitempty"`
	QASHA          string `json:"qa_sha"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	WorkflowRunID  string `json:"workflow_run_id,omitempty"`
}

// CaseResult is a sanitized result projection. Detail must contain only a
// classification and never raw process, request, response, or credential data.
type CaseResult struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	DurationMS int64  `json:"duration_ms"`
	Detail     string `json:"detail,omitempty"`
}

// Report is the versioned, immutable acceptance evidence schema.
type Report struct {
	SchemaVersion int          `json:"schema_version"`
	Binding       Binding      `json:"binding"`
	StartedAt     time.Time    `json:"started_at"`
	CompletedAt   time.Time    `json:"completed_at"`
	GoVersion     string       `json:"go_version"`
	OS            string       `json:"os"`
	Arch          string       `json:"arch"`
	Status        string       `json:"status"`
	Cases         []CaseResult `json:"cases"`
	Gaps          []string     `json:"gaps"`
}

// Validate rejects non-canonical Git object IDs and artifact digests.
func (b Binding) Validate() error {
	for _, field := range []struct {
		name     string
		value    string
		length   int
		optional bool
	}{
		{"source_sha", b.SourceSHA, 40, false},
		{"head_sha", b.HeadSHA, 40, true},
		{"base_sha", b.BaseSHA, 40, true},
		{"qa_sha", b.QASHA, 40, false},
		{"artifact_sha256", b.ArtifactSHA256, 64, false},
	} {
		if field.optional && field.value == "" {
			continue
		}
		if !isLowerHex(field.value, field.length) {
			return fmt.Errorf("invalid %s", field.name)
		}
	}
	return nil
}

// Validate enforces schema, required-case and confidentiality invariants.
func (r Report) Validate(requiredCases, forbiddenCanaries []string) error {
	if r.SchemaVersion != SchemaVersion {
		return errors.New("invalid schema_version")
	}
	if err := r.Binding.Validate(); err != nil {
		return err
	}
	if r.StartedAt.IsZero() || r.CompletedAt.IsZero() || r.CompletedAt.Before(r.StartedAt) {
		return errors.New("invalid report timestamps")
	}
	if strings.TrimSpace(r.GoVersion) == "" {
		return errors.New("missing go_version")
	}
	if strings.TrimSpace(r.OS) == "" {
		return errors.New("missing os")
	}
	if strings.TrimSpace(r.Arch) == "" {
		return errors.New("missing arch")
	}
	if r.Status != StatusPass && r.Status != StatusFail {
		return errors.New("invalid report status")
	}

	results := make(map[string]string, len(r.Cases))
	for _, result := range r.Cases {
		if strings.TrimSpace(result.Name) == "" {
			return errors.New("case name is required")
		}
		if _, exists := results[result.Name]; exists {
			return errors.New("duplicate case name")
		}
		if result.Status != StatusPass && result.Status != StatusFail && result.Status != StatusNotRun {
			return errors.New("invalid case status")
		}
		if result.DurationMS < 0 {
			return errors.New("invalid case duration_ms")
		}
		if result.Detail != "" && !detailClassification.MatchString(result.Detail) {
			return errors.New("invalid case detail classification")
		}
		results[result.Name] = result.Status
	}
	seenRequired := make(map[string]struct{}, len(requiredCases))
	for _, name := range requiredCases {
		if strings.TrimSpace(name) == "" {
			return errors.New("required case name is empty")
		}
		if _, duplicate := seenRequired[name]; duplicate {
			return errors.New("duplicate required case name")
		}
		seenRequired[name] = struct{}{}
		if results[name] != StatusPass {
			return errors.New("required case did not pass")
		}
	}
	if r.Status == StatusPass {
		if len(r.Gaps) != 0 {
			return errors.New("passing report contains gaps")
		}
		for _, status := range results {
			if status != StatusPass {
				return errors.New("passing report contains failed case")
			}
		}
	}

	serialized, err := json.Marshal(r)
	if err != nil {
		return errors.New("serialize report for confidentiality validation")
	}
	for _, canary := range forbiddenCanaries {
		if serializedContainsCanary(serialized, canary) {
			return errors.New("report contains forbidden canary")
		}
	}
	return nil
}

// WriteAtomicExclusive makes a complete report visible exactly once with mode
// 0600. A hard link supplies atomic no-replace publication on the same volume.
func WriteAtomicExclusive(path string, r Report, requiredCases, forbiddenCanaries []string) error {
	if err := r.Validate(requiredCases, forbiddenCanaries); err != nil {
		return err
	}
	serialized, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return errors.New("serialize evidence")
	}
	serialized = append(serialized, '\n')
	for _, canary := range forbiddenCanaries {
		if serializedContainsCanary(serialized, canary) {
			return errors.New("serialized evidence contains forbidden canary")
		}
	}
	if len(serialized) > maxReportSize {
		return errors.New("serialized evidence exceeds size limit")
	}

	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".evidence-*.tmp")
	if err != nil {
		return fmt.Errorf("create evidence temporary file: %w", err)
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()

	succeeded := false
	defer func() {
		if !succeeded {
			_ = temp.Close()
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return fmt.Errorf("secure evidence temporary file: %w", err)
	}
	if _, err := temp.Write(serialized); err != nil {
		return fmt.Errorf("write evidence temporary file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync evidence temporary file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close evidence temporary file: %w", err)
	}
	if err := os.Link(tempName, path); err != nil {
		return fmt.Errorf("publish evidence exclusively: %w", err)
	}
	if err := syncDirectory(dir); err != nil {
		_ = os.Remove(path)
		return err
	}
	succeeded = true
	return nil
}

// ReadAndVerify parses evidence strictly and compares it with an independently
// supplied binding. It never treats values inside the report as expectations.
func ReadAndVerify(path string, expected Binding, requiredCases, forbiddenCanaries []string) (Report, error) {
	var report Report
	if err := expected.Validate(); err != nil {
		return report, fmt.Errorf("invalid external binding: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return report, fmt.Errorf("stat evidence: %w", err)
	}
	if !info.Mode().IsRegular() {
		return report, errors.New("evidence is not a regular file")
	}
	if info.Mode().Perm() != 0o600 {
		return report, errors.New("evidence mode is not 0600")
	}
	if info.Size() > maxReportSize {
		return report, errors.New("evidence exceeds size limit")
	}

	file, err := os.Open(path)
	if err != nil {
		return report, fmt.Errorf("open evidence: %w", err)
	}
	defer file.Close()
	reader := bufio.NewReader(io.LimitReader(file, maxReportSize+1))
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		return Report{}, errors.New("decode evidence")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Report{}, errors.New("evidence contains trailing data")
	}
	if err := report.Validate(requiredCases, forbiddenCanaries); err != nil {
		return Report{}, err
	}
	if report.Binding != expected {
		return Report{}, errors.New("evidence binding does not match external expectation")
	}
	return report, nil
}

// SHA256File computes the canonical lowercase digest of a file.
func SHA256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open artifact: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash artifact: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func isLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func serializedContainsCanary(serialized []byte, canary string) bool {
	if canary == "" {
		return false
	}
	if bytes.Contains(serialized, []byte(canary)) {
		return true
	}
	escaped, err := json.Marshal(canary)
	if err != nil || len(escaped) < 2 {
		return false
	}
	return bytes.Contains(serialized, escaped[1:len(escaped)-1])
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open evidence directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync evidence directory: %w", err)
	}
	return nil
}
