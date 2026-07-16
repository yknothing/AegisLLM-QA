// Package oracle detects test canaries on surfaces where their appearance is
// forbidden. Findings intentionally expose labels and counts, never raw values.
package oracle

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sync"
)

// Surface identifies an observable QA boundary.
type Surface string

const (
	SurfaceProcessEnvironment Surface = "process_environment"
	SurfaceConfigFile         Surface = "config_file"
	SurfaceTokenFile          Surface = "token_file"
	SurfaceClientInput        Surface = "client_input"
	SurfaceStdout             Surface = "stdout"
	SurfaceStderr             Surface = "stderr"
	SurfaceGatewayResponse    Surface = "gateway_response"
	SurfaceProviderRequest    Surface = "provider_request"
	SurfaceProviderResponse   Surface = "provider_response"
	SurfaceFileTree           Surface = "file_tree"
)

// Label names a canary without revealing its value.
type Label string

const (
	LabelMasterKey     Label = "master_key"
	LabelJWTSigningKey Label = "jwt_signing_key"
	LabelProviderKey   Label = "provider_key"
	LabelPrompt        Label = "prompt"
	LabelCompletion    Label = "completion"
	LabelError         Label = "error"
	LabelVirtualToken  Label = "virtual_token"
)

var (
	// ErrScanTree reports a filesystem scan failure without disclosing a path
	// that may itself contain a registered canary.
	ErrScanTree = errors.New("oracle tree scan failed")

	labelOrder = []Label{
		LabelMasterKey,
		LabelJWTSigningKey,
		LabelProviderKey,
		LabelPrompt,
		LabelCompletion,
		LabelError,
		LabelVirtualToken,
	}
	validSurfaces = map[Surface]struct{}{
		SurfaceProcessEnvironment: {},
		SurfaceConfigFile:         {},
		SurfaceTokenFile:          {},
		SurfaceClientInput:        {},
		SurfaceStdout:             {},
		SurfaceStderr:             {},
		SurfaceGatewayResponse:    {},
		SurfaceProviderRequest:    {},
		SurfaceProviderResponse:   {},
		SurfaceFileTree:           {},
	}
)

const (
	maxScanFileBytes  = 1 << 20
	maxScanFiles      = 1024
	maxScanTotalBytes = 16 << 20
)

// Finding reports a forbidden canary occurrence. It deliberately has no raw
// value or path field so diagnostic serialization cannot disclose secrets.
type Finding struct {
	Label   Label   `json:"label"`
	Surface Surface `json:"surface"`
	Count   int     `json:"count"`
}

type canary struct {
	label Label
	value []byte
}

// Set contains random values used by one isolated QA case. The exported values
// are inputs for the harness; internal scanner state uses defensive copies.
type Set struct {
	MasterKey     string
	JWTSigningKey string
	ProviderKey   string
	Prompt        string
	Completion    string
	Error         string

	mu       sync.RWMutex
	canaries []canary
	allowed  map[Surface]map[Label]struct{}
	tokens   map[[sha256.Size]byte]struct{}
}

// GenerateSet creates independent cryptographically random canaries and the
// narrow default allowlist needed by the black-box QA flow.
func GenerateSet() (*Set, error) {
	master, err := randomHex(32)
	if err != nil {
		return nil, fmt.Errorf("generate master-key canary: %w", err)
	}
	jwt, err := randomTagged("jwt", 32)
	if err != nil {
		return nil, fmt.Errorf("generate JWT canary: %w", err)
	}
	provider, err := randomTagged("provider", 24)
	if err != nil {
		return nil, fmt.Errorf("generate provider canary: %w", err)
	}
	prompt, err := randomTagged("prompt", 24)
	if err != nil {
		return nil, fmt.Errorf("generate prompt canary: %w", err)
	}
	completion, err := randomTagged("completion", 24)
	if err != nil {
		return nil, fmt.Errorf("generate completion canary: %w", err)
	}
	errorValue, err := randomTagged("error", 24)
	if err != nil {
		return nil, fmt.Errorf("generate error canary: %w", err)
	}

	set := &Set{
		MasterKey:     master,
		JWTSigningKey: jwt,
		ProviderKey:   provider,
		Prompt:        prompt,
		Completion:    completion,
		Error:         errorValue,
		allowed:       make(map[Surface]map[Label]struct{}),
		tokens:        make(map[[sha256.Size]byte]struct{}),
	}
	set.canaries = []canary{
		{label: LabelMasterKey, value: []byte(master)},
		{label: LabelJWTSigningKey, value: []byte(jwt)},
		{label: LabelProviderKey, value: []byte(provider)},
		{label: LabelPrompt, value: []byte(prompt)},
		{label: LabelCompletion, value: []byte(completion)},
		{label: LabelError, value: []byte(errorValue)},
	}
	set.allowLocked(SurfaceProcessEnvironment, LabelMasterKey, LabelJWTSigningKey)
	set.allowLocked(SurfaceClientInput, LabelProviderKey, LabelPrompt)
	set.allowLocked(SurfaceProviderRequest, LabelProviderKey, LabelPrompt)
	set.allowLocked(SurfaceProviderResponse, LabelCompletion, LabelError)
	set.allowLocked(SurfaceGatewayResponse, LabelCompletion)
	return set, nil
}

// Allow expands the allowlist for a static canary. A virtual token is always
// restricted to token-file and client-input surfaces.
func (s *Set) Allow(surface Surface, labels ...Label) error {
	if s == nil {
		return errors.New("oracle set is nil")
	}
	if _, ok := validSurfaces[surface]; !ok {
		return fmt.Errorf("unknown oracle surface %q", surface)
	}
	for _, label := range labels {
		if !knownLabel(label) {
			return fmt.Errorf("unknown oracle label %q", label)
		}
		if label == LabelVirtualToken && surface != SurfaceTokenFile && surface != SurfaceClientInput {
			return errors.New("virtual tokens may only be allowed in token files and client input")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowLocked(surface, labels...)
	return nil
}

// RegisterVirtualToken adds a newly issued token using a defensive copy. Its
// allowlist is fixed to token-file and client-input surfaces.
func (s *Set) RegisterVirtualToken(token []byte) error {
	if s == nil {
		return errors.New("oracle set is nil")
	}
	if len(token) == 0 {
		return errors.New("virtual token must not be empty")
	}
	if len(token) > 64<<10 {
		return errors.New("virtual token exceeds 64 KiB")
	}
	value := append([]byte(nil), token...)
	key := sha256.Sum256(value)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tokens[key]; exists {
		return nil
	}
	s.tokens[key] = struct{}{}
	s.canaries = append(s.canaries, canary{label: LabelVirtualToken, value: value})
	s.allowLocked(SurfaceTokenFile, LabelVirtualToken)
	s.allowLocked(SurfaceClientInput, LabelVirtualToken)
	return nil
}

// ScanBytes counts canaries forbidden on surface. Returned findings contain
// only label, surface, and count.
func (s *Set) ScanBytes(surface Surface, data []byte) []Finding {
	if s == nil || len(data) == 0 {
		return nil
	}
	s.mu.RLock()
	counts := make(map[Label]int)
	for _, item := range s.canaries {
		if s.isAllowedLocked(surface, item.label) {
			continue
		}
		counts[item.label] += bytes.Count(data, item.value)
	}
	s.mu.RUnlock()
	return findingsForCounts(surface, counts)
}

// ScanTree scans regular files below root without following symlinks and
// aggregates results so paths and raw values never enter findings. Each file
// buffer is cleared immediately after its canaries are counted.
func (s *Set) ScanTree(surface Surface, root string) ([]Finding, error) {
	if s == nil {
		return nil, ErrScanTree
	}
	counts := make(map[Label]int)
	fileCount := 0
	totalBytes := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return ErrScanTree
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return ErrScanTree
		}
		if entry.IsDir() || !entry.Type().IsRegular() {
			return nil
		}
		fileCount++
		if fileCount > maxScanFiles {
			return ErrScanTree
		}
		data, err := readScanFile(path)
		if err != nil {
			return ErrScanTree
		}
		totalBytes += len(data)
		if totalBytes > maxScanTotalBytes {
			clear(data)
			return ErrScanTree
		}
		for _, finding := range s.ScanBytes(surface, data) {
			counts[finding.Label] += finding.Count
		}
		clear(data)
		return nil
	})
	if err != nil {
		return nil, ErrScanTree
	}
	return findingsForCounts(surface, counts), nil
}

func (s *Set) allowLocked(surface Surface, labels ...Label) {
	if s.allowed[surface] == nil {
		s.allowed[surface] = make(map[Label]struct{})
	}
	for _, label := range labels {
		s.allowed[surface][label] = struct{}{}
	}
}

func (s *Set) isAllowedLocked(surface Surface, label Label) bool {
	_, ok := s.allowed[surface][label]
	return ok
}

func findingsForCounts(surface Surface, counts map[Label]int) []Finding {
	findings := make([]Finding, 0, len(counts))
	for _, label := range labelOrder {
		if count := counts[label]; count > 0 {
			findings = append(findings, Finding{Label: label, Surface: surface, Count: count})
		}
	}
	return findings
}

func knownLabel(candidate Label) bool {
	for _, label := range labelOrder {
		if label == candidate {
			return true
		}
	}
	return false
}

func randomTagged(tag string, byteCount int) (string, error) {
	random, err := randomHex(byteCount)
	if err != nil {
		return "", err
	}
	return tag + "_qa_" + random, nil
}

func randomHex(byteCount int) (string, error) {
	raw := make([]byte, byteCount)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	encoded := hex.EncodeToString(raw)
	clear(raw)
	return encoded, nil
}
