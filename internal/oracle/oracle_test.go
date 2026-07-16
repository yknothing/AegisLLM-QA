package oracle

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestGenerateSetProducesDistinctUsableCanaries(t *testing.T) {
	set, err := GenerateSet()
	if err != nil {
		t.Fatalf("GenerateSet: %v", err)
	}
	values := []string{set.MasterKey, set.JWTSigningKey, set.ProviderKey, set.Prompt, set.Completion, set.Error}
	seen := make(map[string]struct{}, len(values))
	for i, value := range values {
		if value == "" {
			t.Fatalf("canary %d is empty", i)
		}
		if _, exists := seen[value]; exists {
			t.Fatalf("duplicate canary at index %d", i)
		}
		seen[value] = struct{}{}
	}
	master, err := hex.DecodeString(set.MasterKey)
	if err != nil || len(master) != 32 {
		t.Fatalf("master key is not 32-byte hex: len=%d err=%v", len(master), err)
	}
	if len(set.JWTSigningKey) < 32 {
		t.Fatalf("JWT key length = %d, want >=32", len(set.JWTSigningKey))
	}
}

func TestScanBytesHonorsPerSurfaceAllowlistAndDoesNotReturnRaw(t *testing.T) {
	set, err := GenerateSet()
	if err != nil {
		t.Fatalf("GenerateSet: %v", err)
	}

	env := []byte("AEGIS_QA_MASTER_KEY=" + set.MasterKey)
	if findings := set.ScanBytes(SurfaceProcessEnvironment, env); len(findings) != 0 {
		t.Fatalf("allowed environment value reported: %#v", findings)
	}
	findings := set.ScanBytes(SurfaceStdout, []byte(set.MasterKey+"/"+set.MasterKey+"/"+set.ProviderKey))
	want := []Finding{
		{Label: LabelMasterKey, Surface: SurfaceStdout, Count: 2},
		{Label: LabelProviderKey, Surface: SurfaceStdout, Count: 1},
	}
	if !reflect.DeepEqual(findings, want) {
		t.Fatalf("findings = %#v, want %#v", findings, want)
	}
	raw, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("marshal findings: %v", err)
	}
	for _, secret := range []string{set.MasterKey, set.ProviderKey} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("finding leaked raw canary: %s", raw)
		}
	}
}

func TestVirtualTokenIsDynamicallyRegisteredAndOnlyAllowedAtInputBoundaries(t *testing.T) {
	set, err := GenerateSet()
	if err != nil {
		t.Fatalf("GenerateSet: %v", err)
	}
	token := []byte("eyJ.qa-virtual-token-canary.signature")
	if err := set.RegisterVirtualToken(token); err != nil {
		t.Fatalf("RegisterVirtualToken: %v", err)
	}
	token[0] = 'X'
	original := []byte("eyJ.qa-virtual-token-canary.signature")
	for _, surface := range []Surface{SurfaceTokenFile, SurfaceClientInput} {
		if findings := set.ScanBytes(surface, original); len(findings) != 0 {
			t.Fatalf("token reported on allowed surface %s: %#v", surface, findings)
		}
	}
	for _, surface := range []Surface{SurfaceStdout, SurfaceStderr, SurfaceGatewayResponse, SurfaceFileTree, SurfaceProviderRequest} {
		findings := set.ScanBytes(surface, original)
		want := []Finding{{Label: LabelVirtualToken, Surface: surface, Count: 1}}
		if !reflect.DeepEqual(findings, want) {
			t.Fatalf("surface %s findings = %#v, want %#v", surface, findings, want)
		}
	}
	if err := set.Allow(SurfaceStdout, LabelVirtualToken); err == nil {
		t.Fatal("Allow expanded virtual token beyond token file/client input")
	}
}

func TestScanTreeAggregatesFindingsWithoutReturningPathsOrRaw(t *testing.T) {
	set, err := GenerateSet()
	if err != nil {
		t.Fatalf("GenerateSet: %v", err)
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "one.log"), []byte(set.Error+" "+set.Error), 0600); err != nil {
		t.Fatalf("write one: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "two.log"), []byte(set.Error+" "+set.Prompt), 0600); err != nil {
		t.Fatalf("write two: %v", err)
	}
	findings, err := set.ScanTree(SurfaceFileTree, root)
	if err != nil {
		t.Fatalf("ScanTree: %v", err)
	}
	want := []Finding{
		{Label: LabelPrompt, Surface: SurfaceFileTree, Count: 1},
		{Label: LabelError, Surface: SurfaceFileTree, Count: 3},
	}
	if !reflect.DeepEqual(findings, want) {
		t.Fatalf("findings = %#v, want %#v", findings, want)
	}
	raw, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("marshal findings: %v", err)
	}
	for _, forbidden := range []string{root, "one.log", "two.log", set.Error, set.Prompt} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("finding exposed path/raw value %q: %s", forbidden, raw)
		}
	}
}

func TestScanTreeFailsClosedOnMissingRootsAndSymlinksWithoutLeakingPaths(t *testing.T) {
	set, err := GenerateSet()
	if err != nil {
		t.Fatalf("GenerateSet: %v", err)
	}
	missing := filepath.Join(t.TempDir(), set.ProviderKey)
	if _, err := set.ScanTree(SurfaceFileTree, missing); err == nil || !errors.Is(err, ErrScanTree) {
		t.Fatalf("missing-root error = %v, want ErrScanTree", err)
	} else if strings.Contains(err.Error(), set.ProviderKey) || strings.Contains(err.Error(), missing) {
		t.Fatalf("missing-root error leaked raw path: %v", err)
	}

	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, []byte(set.MasterKey), 0600); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(root, "linked")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	_, err = set.ScanTree(SurfaceFileTree, root)
	requireSanitizedScanTreeError(t, err, root, target, set.MasterKey)
}

func TestScanTreeFileOpenRejectsFinalSymlinkAfterDirectoryEntrySwap(t *testing.T) {
	set, err := GenerateSet()
	if err != nil {
		t.Fatalf("GenerateSet: %v", err)
	}
	root := t.TempDir()
	victim := filepath.Join(root, "victim")
	if err := os.WriteFile(victim, []byte("safe"), 0600); err != nil {
		t.Fatalf("write initial file: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read root: %v", err)
	}
	if len(entries) != 1 || !entries[0].Type().IsRegular() {
		t.Fatalf("initial directory entry is not regular: %#v", entries)
	}

	target := filepath.Join(t.TempDir(), set.ProviderKey)
	if err := os.WriteFile(target, []byte(set.MasterKey), 0600); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}
	if err := os.Remove(victim); err != nil {
		t.Fatalf("remove initial file: %v", err)
	}
	if err := os.Symlink(target, victim); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	data, err := readScanFile(victim)
	if len(data) != 0 {
		t.Fatalf("readScanFile returned %d bytes through swapped symlink", len(data))
	}
	requireSanitizedScanTreeError(t, err, victim, target, set.ProviderKey, set.MasterKey)
}

func TestScanTreeRejectsSingleFileExceedingOneMiB(t *testing.T) {
	set, err := GenerateSet()
	if err != nil {
		t.Fatalf("GenerateSet: %v", err)
	}
	root := t.TempDir()
	path := filepath.Join(root, set.ProviderKey)
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), (1<<20)+1), 0600); err != nil {
		t.Fatalf("write oversized file: %v", err)
	}

	_, err = set.ScanTree(SurfaceFileTree, root)
	requireSanitizedScanTreeError(t, err, root, path, set.ProviderKey)
}

func TestScanTreeRejectsMoreThan1024Files(t *testing.T) {
	set, err := GenerateSet()
	if err != nil {
		t.Fatalf("GenerateSet: %v", err)
	}
	root := t.TempDir()
	for i := 0; i < 1025; i++ {
		name := fmt.Sprintf("%04d", i)
		if i == 1024 {
			name = set.ProviderKey
		}
		if err := os.WriteFile(filepath.Join(root, name), nil, 0600); err != nil {
			t.Fatalf("write file %d: %v", i, err)
		}
	}

	_, err = set.ScanTree(SurfaceFileTree, root)
	requireSanitizedScanTreeError(t, err, root, set.ProviderKey)
}

func TestScanTreeRejectsMoreThan16MiBTotal(t *testing.T) {
	set, err := GenerateSet()
	if err != nil {
		t.Fatalf("GenerateSet: %v", err)
	}
	root := t.TempDir()
	data := bytes.Repeat([]byte("x"), 1<<20)
	for i := 0; i < 17; i++ {
		name := fmt.Sprintf("%02d", i)
		if i == 16 {
			name = set.ProviderKey
		}
		if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
			t.Fatalf("write file %d: %v", i, err)
		}
	}

	_, err = set.ScanTree(SurfaceFileTree, root)
	requireSanitizedScanTreeError(t, err, root, set.ProviderKey)
}

func TestScanTreeReturnsOnlySentinelForNilSet(t *testing.T) {
	var set *Set
	_, err := set.ScanTree(SurfaceFileTree, t.TempDir())
	requireSanitizedScanTreeError(t, err)
}

func requireSanitizedScanTreeError(t *testing.T, err error, forbidden ...string) {
	t.Helper()
	if err != ErrScanTree {
		t.Fatalf("ScanTree error = %v, want exact ErrScanTree", err)
	}
	for _, value := range forbidden {
		if value != "" && strings.Contains(err.Error(), value) {
			t.Fatalf("ScanTree error leaked forbidden value %q: %v", value, err)
		}
	}
}

func TestOracleSupportsConcurrentScanAndRegistration(t *testing.T) {
	set, err := GenerateSet()
	if err != nil {
		t.Fatalf("GenerateSet: %v", err)
	}
	const workers = 24
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = set.ScanBytes(SurfaceStdout, []byte(set.ProviderKey))
		}()
		go func(i int) {
			defer wg.Done()
			_ = set.RegisterVirtualToken([]byte("virtual-" + strings.Repeat("x", i+16)))
		}(i)
	}
	wg.Wait()
}
