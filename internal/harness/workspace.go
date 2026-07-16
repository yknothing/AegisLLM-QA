package harness

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/yknothing/AegisLLM-QA/internal/oracle"
)

const (
	MasterKeyEnv     = "AEGIS_QA_MASTER_KEY"
	JWTSigningKeyEnv = "AEGIS_QA_JWT_SIGNING_KEY"
	ProviderKeyID    = "qa-provider-key"
	ProviderID       = "qa-openai-provider"
	Model            = "qa-model"
)

// Canaries contains the random values assigned to one case. Master and JWT
// values are placed only in the sanitized child environment; the provider key
// is intended for operator stdin, and content canaries are request fixtures.
type Canaries struct {
	MasterKey     string
	JWTSigningKey string
	ProviderKey   string
	Prompt        string
	Completion    string
	Error         string
}

// Workspace owns the private filesystem and configuration for one QA case.
type Workspace struct {
	RootDir        string
	ConfigFile     string
	RootCAFile     string
	KeyStoreDir    string
	RevocationFile string
	GatewayAddress string
	GatewayURL     string
	Canaries       Canaries
	Oracle         *oracle.Set

	privateRoot string
	environment []string
	closeOnce   sync.Once
	closeErr    error
}

// New creates an isolated owner-only case directory and an independently
// modeled Aegis JSON configuration targeting the TLS loopback provider.
func New(providerURL, rootCAFile string) (*Workspace, error) {
	provider, err := validateProviderURL(providerURL)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(rootCAFile) // #nosec G304 -- explicit QA trust anchor selected by the caller.
	if err != nil {
		return nil, fmt.Errorf("read provider root CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("provider root CA does not contain a PEM certificate")
	}

	root, err := os.MkdirTemp("", "aegisllm-qa-case-")
	if err != nil {
		return nil, fmt.Errorf("create workspace: %w", err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		_ = os.RemoveAll(root)
		return nil, fmt.Errorf("secure workspace: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(root)
		}
	}()

	canarySet, err := oracle.GenerateSet()
	if err != nil {
		return nil, err
	}
	address, err := ephemeralLoopbackAddress()
	if err != nil {
		return nil, err
	}
	workspace := &Workspace{
		RootDir:        root,
		ConfigFile:     filepath.Join(root, "aegis.json"),
		RootCAFile:     filepath.Join(root, "provider-root-ca.pem"),
		KeyStoreDir:    filepath.Join(root, "keys"),
		RevocationFile: filepath.Join(root, "revocations.json"),
		GatewayAddress: address,
		GatewayURL:     "http://" + address,
		Canaries: Canaries{
			MasterKey:     canarySet.MasterKey,
			JWTSigningKey: canarySet.JWTSigningKey,
			ProviderKey:   canarySet.ProviderKey,
			Prompt:        canarySet.Prompt,
			Completion:    canarySet.Completion,
			Error:         canarySet.Error,
		},
		Oracle:      canarySet,
		privateRoot: root,
	}
	for _, directory := range []string{workspace.KeyStoreDir, filepath.Join(root, "home"), filepath.Join(root, "tmp")} {
		if err := os.Mkdir(directory, 0700); err != nil {
			return nil, fmt.Errorf("create private workspace directory: %w", err)
		}
	}
	if err := writePrivateFile(workspace.RootCAFile, caPEM); err != nil {
		return nil, fmt.Errorf("copy provider root CA: %w", err)
	}
	revocation := struct {
		Version    int   `json:"version"`
		Generation int   `json:"generation"`
		UpdatedAt  int64 `json:"updated_at"`
		Entries    []any `json:"entries"`
	}{Version: 1, Generation: 1, UpdatedAt: time.Now().UTC().Unix(), Entries: []any{}}
	if err := writeJSONFile(workspace.RevocationFile, revocation); err != nil {
		return nil, fmt.Errorf("write revocation snapshot: %w", err)
	}

	cfg := newAegisConfig(workspace, provider.String(), provider.Hostname())
	if err := writeJSONFile(workspace.ConfigFile, cfg); err != nil {
		return nil, fmt.Errorf("write Aegis config: %w", err)
	}
	workspace.environment = []string{
		"HOME=" + filepath.Join(root, "home"),
		"TMPDIR=" + filepath.Join(root, "tmp"),
		"PATH=/usr/bin:/bin",
		"LANG=C",
		"SSL_CERT_FILE=" + workspace.RootCAFile,
		MasterKeyEnv + "=" + workspace.Canaries.MasterKey,
		JWTSigningKeyEnv + "=" + workspace.Canaries.JWTSigningKey,
	}
	cleanup = false
	return workspace, nil
}

// Environment returns the complete sanitized environment for child processes;
// callers must assign it to exec.Cmd.Env instead of appending os.Environ.
func (w *Workspace) Environment() []string {
	if w == nil {
		return nil
	}
	return append([]string(nil), w.environment...)
}

// Close removes this workspace's original private root and is idempotent.
func (w *Workspace) Close() error {
	if w == nil {
		return nil
	}
	w.closeOnce.Do(func() {
		if w.privateRoot == "" || filepath.Dir(w.privateRoot) != filepath.Clean(os.TempDir()) || !strings.HasPrefix(filepath.Base(w.privateRoot), "aegisllm-qa-case-") {
			w.closeErr = errors.New("refusing to remove invalid QA workspace root")
			return
		}
		w.closeErr = os.RemoveAll(w.privateRoot)
	})
	return w.closeErr
}

type aegisConfig struct {
	Server    serverConfig     `json:"server"`
	KMS       kmsConfig        `json:"kms"`
	Providers []providerConfig `json:"providers"`
	Auth      authConfig       `json:"auth"`
	RateLimit rateLimitConfig  `json:"rate_limit"`
	Quota     quotaConfig      `json:"quota"`
	Egress    egressConfig     `json:"egress"`
}

type serverConfig struct {
	Address            string `json:"address"`
	ReadTimeout        string `json:"read_timeout"`
	WriteTimeout       string `json:"write_timeout"`
	ShutdownTimeout    string `json:"shutdown_timeout"`
	MaxRequestBodySize int64  `json:"max_request_body_size"`
}

type kmsConfig struct {
	Mode  string         `json:"mode"`
	Local localKMSConfig `json:"local"`
}

type localKMSConfig struct {
	MasterKeyEnv           string `json:"master_key_env"`
	KeyStorePath           string `json:"key_store_path"`
	MinimumEnvelopeVersion int    `json:"minimum_envelope_version"`
}

type providerConfig struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	BaseURL  string   `json:"base_url"`
	APIKeyID string   `json:"api_key_id"`
	Models   []string `json:"models"`
	Weight   int      `json:"weight"`
	MaxRPM   int      `json:"max_rpm"`
	MaxTPM   int      `json:"max_tpm"`
	Enabled  bool     `json:"enabled"`
	Priority int      `json:"priority"`
}

type authConfig struct {
	JWTSigningKeyEnv string           `json:"jwt_signing_key_env"`
	TokenExpiry      string           `json:"token_expiry"`
	Issuer           string           `json:"issuer"`
	Revocation       revocationConfig `json:"revocation"`
}

type revocationConfig struct {
	Backend         string `json:"backend"`
	FilePath        string `json:"file_path"`
	RefreshInterval string `json:"refresh_interval"`
}

type rateLimitConfig struct {
	Enabled               bool   `json:"enabled"`
	Backend               string `json:"backend"`
	DefaultRPM            int    `json:"default_rpm"`
	DefaultTPM            int    `json:"default_tpm"`
	DefaultMaxConcurrency int    `json:"default_max_concurrency"`
}

type quotaConfig struct {
	Enabled bool `json:"enabled"`
}

type egressConfig struct {
	AllowedDomains []string `json:"allowed_domains"`
}

func newAegisConfig(workspace *Workspace, providerURL, providerHost string) aegisConfig {
	return aegisConfig{
		Server: serverConfig{
			Address:            workspace.GatewayAddress,
			ReadTimeout:        "5s",
			WriteTimeout:       "15s",
			ShutdownTimeout:    "5s",
			MaxRequestBodySize: 1 << 20,
		},
		KMS: kmsConfig{Mode: "local", Local: localKMSConfig{
			MasterKeyEnv:           MasterKeyEnv,
			KeyStorePath:           workspace.KeyStoreDir,
			MinimumEnvelopeVersion: 2,
		}},
		Providers: []providerConfig{{
			ID: ProviderID, Name: "QA OpenAI Provider", Type: "openai", BaseURL: providerURL,
			APIKeyID: ProviderKeyID, Models: []string{Model}, Weight: 1, Enabled: true, Priority: 1,
		}},
		Auth: authConfig{
			JWTSigningKeyEnv: JWTSigningKeyEnv,
			TokenExpiry:      "1h",
			Issuer:           "aegis",
			Revocation: revocationConfig{
				Backend: "file", FilePath: workspace.RevocationFile, RefreshInterval: "100ms",
			},
		},
		RateLimit: rateLimitConfig{
			Enabled: true, Backend: "memory", DefaultRPM: 120, DefaultMaxConcurrency: 16,
		},
		Quota:  quotaConfig{Enabled: false},
		Egress: egressConfig{AllowedDomains: []string{providerHost}},
	}
}

func validateProviderURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("provider URL is invalid")
	}
	if parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.Port() == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("provider URL must be an HTTPS loopback origin")
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, errors.New("provider URL must use a loopback host")
	}
	return parsed, nil
}

func ephemeralLoopbackAddress() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("allocate gateway address: %w", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		return "", fmt.Errorf("release gateway address: %w", err)
	}
	return address, nil
}

func writeJSONFile(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return writePrivateFile(path, encoded)
}
