package harness

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/yknothing/AegisLLM-QA/internal/oracle"
)

func TestWorkspaceIsPrivateIsolatedAndProducesAegisConfig(t *testing.T) {
	provider, err := Start()
	if err != nil {
		t.Fatalf("Start provider: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })

	one, err := New(provider.URL(), provider.RootCAFile())
	if err != nil {
		t.Fatalf("New workspace one: %v", err)
	}
	t.Cleanup(func() { _ = one.Close() })
	two, err := New(provider.URL(), provider.RootCAFile())
	if err != nil {
		t.Fatalf("New workspace two: %v", err)
	}
	t.Cleanup(func() { _ = two.Close() })

	if one.RootDir == two.RootDir {
		t.Fatal("workspaces reused a root directory")
	}
	if one.GatewayAddress == two.GatewayAddress {
		t.Fatal("workspaces reused a gateway address")
	}
	if one.Canaries == two.Canaries {
		t.Fatal("workspaces reused canaries")
	}
	for _, workspace := range []*Workspace{one, two} {
		info, err := os.Stat(workspace.RootDir)
		if err != nil {
			t.Fatalf("stat root: %v", err)
		}
		if got := info.Mode().Perm(); got != 0700 {
			t.Fatalf("root mode = %o, want 700", got)
		}
		for _, path := range []string{workspace.ConfigFile, workspace.RootCAFile, workspace.RevocationFile} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat %s: %v", filepath.Base(path), err)
			}
			if got := info.Mode().Perm(); got != 0600 {
				t.Fatalf("%s mode = %o, want 600", filepath.Base(path), got)
			}
		}
		findings := workspace.Oracle.ScanBytes(oracle.SurfaceStdout, []byte(workspace.Canaries.ProviderKey))
		if len(findings) != 1 || findings[0].Label != oracle.LabelProviderKey {
			t.Fatalf("workspace oracle is not bound to its canaries: %#v", findings)
		}
	}

	raw, err := os.ReadFile(one.ConfigFile)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg struct {
		Server struct {
			Address string `json:"address"`
		} `json:"server"`
		KMS struct {
			Mode  string `json:"mode"`
			Local struct {
				MasterKeyEnv           string `json:"master_key_env"`
				KeyStorePath           string `json:"key_store_path"`
				MinimumEnvelopeVersion int    `json:"minimum_envelope_version"`
			} `json:"local"`
		} `json:"kms"`
		Providers []struct {
			BaseURL  string `json:"base_url"`
			APIKeyID string `json:"api_key_id"`
			Enabled  bool   `json:"enabled"`
		} `json:"providers"`
		Auth struct {
			JWTSigningKeyEnv string `json:"jwt_signing_key_env"`
			Revocation       struct {
				FilePath string `json:"file_path"`
			} `json:"revocation"`
		} `json:"auth"`
		Egress struct {
			AllowedDomains []string `json:"allowed_domains"`
		} `json:"egress"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	host, port, err := net.SplitHostPort(cfg.Server.Address)
	if err != nil || host != "127.0.0.1" || port == "0" || port == "" {
		t.Fatalf("server address = %q, want ephemeral IPv4 loopback: %v", cfg.Server.Address, err)
	}
	if cfg.KMS.Mode != "local" || cfg.KMS.Local.MasterKeyEnv != MasterKeyEnv || cfg.KMS.Local.KeyStorePath != one.KeyStoreDir || cfg.KMS.Local.MinimumEnvelopeVersion != 2 {
		t.Fatalf("unexpected KMS config: %#v", cfg.KMS)
	}
	if len(cfg.Providers) != 1 || cfg.Providers[0].BaseURL != provider.URL() || cfg.Providers[0].APIKeyID != ProviderKeyID || !cfg.Providers[0].Enabled {
		t.Fatalf("unexpected provider config: %#v", cfg.Providers)
	}
	if cfg.Auth.JWTSigningKeyEnv != JWTSigningKeyEnv || cfg.Auth.Revocation.FilePath != one.RevocationFile {
		t.Fatalf("unexpected auth config: %#v", cfg.Auth)
	}
	if len(cfg.Egress.AllowedDomains) != 1 || cfg.Egress.AllowedDomains[0] != "127.0.0.1" {
		t.Fatalf("unexpected egress config: %#v", cfg.Egress)
	}
	for label, value := range map[string]string{
		"master":     one.Canaries.MasterKey,
		"JWT":        one.Canaries.JWTSigningKey,
		"provider":   one.Canaries.ProviderKey,
		"prompt":     one.Canaries.Prompt,
		"completion": one.Canaries.Completion,
		"error":      one.Canaries.Error,
	} {
		if strings.Contains(string(raw), value) {
			t.Fatalf("config contains %s canary", label)
		}
	}
}

func TestWorkspaceEnvironmentIsExplicitSanitizedAndDefensive(t *testing.T) {
	provider, err := Start()
	if err != nil {
		t.Fatalf("Start provider: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })
	t.Setenv("AWS_SECRET_ACCESS_KEY", "host-secret-must-not-pass")
	t.Setenv("UNRELATED_HOST_CANARY", "host-canary-must-not-pass")

	workspace, err := New(provider.URL(), provider.RootCAFile())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = workspace.Close() })

	env := workspace.Environment()
	joined := strings.Join(env, "\n")
	for _, forbidden := range []string{"AWS_SECRET_ACCESS_KEY", "host-secret-must-not-pass", "UNRELATED_HOST_CANARY", workspace.Canaries.ProviderKey, workspace.Canaries.Prompt, workspace.Canaries.Completion, workspace.Canaries.Error} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("sanitized environment contains forbidden value/name %q", forbidden)
		}
	}
	values := envMap(t, env)
	if values[MasterKeyEnv] != workspace.Canaries.MasterKey || values[JWTSigningKeyEnv] != workspace.Canaries.JWTSigningKey {
		t.Fatalf("environment lacks generated gateway secrets: keys=%v", mapKeys(values))
	}
	if values["SSL_CERT_FILE"] != workspace.RootCAFile {
		t.Fatalf("SSL_CERT_FILE = %q, want workspace CA %q (GOOS=%s)", values["SSL_CERT_FILE"], workspace.RootCAFile, runtime.GOOS)
	}
	for _, required := range []string{"HOME", "TMPDIR", "PATH", "LANG"} {
		if values[required] == "" {
			t.Fatalf("sanitized environment lacks %s", required)
		}
	}

	env[0] = "MUTATED=value"
	if strings.HasPrefix(workspace.Environment()[0], "MUTATED=") {
		t.Fatal("Environment did not return a defensive copy")
	}
}

func TestWorkspaceCloseRemovesOnlyItsRoot(t *testing.T) {
	provider, err := Start()
	if err != nil {
		t.Fatalf("Start provider: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })
	workspace, err := New(provider.URL(), provider.RootCAFile())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	root := workspace.RootDir
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0600); err != nil {
		t.Fatalf("write outside marker: %v", err)
	}
	if err := workspace.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("workspace root still exists or stat failed unexpectedly: %v", err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("Close affected outside marker: %v", err)
	}
	if err := workspace.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func envMap(t *testing.T, env []string) map[string]string {
	t.Helper()
	values := make(map[string]string, len(env))
	for _, item := range env {
		name, value, ok := strings.Cut(item, "=")
		if !ok || name == "" {
			t.Fatalf("invalid environment entry %q", item)
		}
		if _, exists := values[name]; exists {
			t.Fatalf("duplicate environment entry %q", name)
		}
		values[name] = value
	}
	return values
}

func mapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}
