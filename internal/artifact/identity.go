// Package artifact verifies that the exact prebuilt SUT is clean, immutable,
// revision-bound, and independently self-identifying.
package artifact

import (
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"

	"github.com/yknothing/AegisLLM-QA/internal/harness"
)

var anchoredVersion = regexp.MustCompile(`\Aaegis ([0-9A-Za-z][0-9A-Za-z._+\-]*) \(commit: ([0-9a-f]{40}), built: ([^()\r\n]+)\)\n?\z`)

// Expected contains externally established artifact identity inputs. Toolchain
// is optional for callers that only record the embedded toolchain; when set it
// is required to match exactly.
type Expected struct {
	SourceSHA      string
	ArtifactSHA256 string
	Toolchain      string
}

// Identity is the verified projection of the immutable SUT.
type Identity struct {
	SourceSHA      string
	ArtifactSHA256 string
	Toolchain      string
	Version        string
	BuildDate      string
	Modified       bool
}

// Inspect performs a pre-execution hash, reads Go build information, executes
// the independent --version contract through the bounded harness, and hashes
// the SUT again before returning.
func Inspect(ctx context.Context, path string, expected Expected) (Identity, error) {
	var identity Identity
	if ctx == nil {
		return identity, errors.New("artifact context is required")
	}
	if !filepath.IsAbs(path) {
		return identity, errors.New("artifact path must be absolute")
	}
	if !isLowerHex(expected.SourceSHA, 40) {
		return identity, errors.New("invalid source_sha")
	}
	if !isLowerHex(expected.ArtifactSHA256, 64) {
		return identity, errors.New("invalid artifact_sha256")
	}
	file, stableInfo, err := openVerifiedArtifact(path)
	if err != nil {
		return identity, err
	}
	defer file.Close()

	preDigest, err := digestOpenFile(file)
	if err != nil {
		return identity, err
	}
	if preDigest != expected.ArtifactSHA256 {
		return identity, errors.New("artifact_sha256 does not match external expectation")
	}

	build, err := buildinfo.Read(file)
	if err != nil {
		return identity, errors.New("read artifact build info")
	}
	revision, revisionFound := buildSetting(build, "vcs.revision")
	if !revisionFound || revision != expected.SourceSHA {
		return identity, errors.New("vcs.revision does not match source_sha")
	}
	modified, modifiedFound := buildSetting(build, "vcs.modified")
	if !modifiedFound || modified != "false" {
		return identity, errors.New("vcs.modified is not false")
	}
	if !strings.HasPrefix(build.GoVersion, "go") || strings.TrimSpace(build.GoVersion) == "" {
		return identity, errors.New("artifact toolchain is invalid")
	}
	if expected.Toolchain != "" && build.GoVersion != expected.Toolchain {
		return identity, errors.New("artifact toolchain does not match expectation")
	}
	if err := verifyArtifactPath(path, stableInfo); err != nil {
		return identity, err
	}

	versionResult, err := harness.Run(ctx, path, []string{"--version"}, nil, nil, 4096)
	if err != nil {
		return identity, errors.New("artifact version command failed")
	}
	if versionResult.Stderr != "" || versionResult.Truncated {
		return identity, errors.New("artifact version output is invalid")
	}
	matches := anchoredVersion.FindStringSubmatch(versionResult.Stdout)
	if matches == nil {
		return identity, errors.New("artifact version output is not anchored")
	}
	if matches[2] != expected.SourceSHA {
		return identity, errors.New("artifact version commit does not match source_sha")
	}

	if err := verifyArtifactPath(path, stableInfo); err != nil {
		return identity, err
	}
	postDigest, err := digestOpenFile(file)
	if err != nil {
		return identity, err
	}
	if err := verifyArtifactPath(path, stableInfo); err != nil {
		return identity, err
	}
	if postDigest != preDigest {
		return identity, errors.New("artifact changed during identity inspection")
	}

	return Identity{
		SourceSHA:      revision,
		ArtifactSHA256: preDigest,
		Toolchain:      build.GoVersion,
		Version:        matches[1],
		BuildDate:      matches[3],
		Modified:       false,
	}, nil
}

// VerifyUnchanged performs the mandatory post-suite hash comparison.
func VerifyUnchanged(path string, identity Identity) error {
	if !isLowerHex(identity.ArtifactSHA256, 64) {
		return errors.New("verified identity artifact_sha256 is invalid")
	}
	file, stableInfo, err := openVerifiedArtifact(path)
	if err != nil {
		return err
	}
	defer file.Close()
	digest, err := digestOpenFile(file)
	if err != nil {
		return err
	}
	if err := verifyArtifactPath(path, stableInfo); err != nil {
		return err
	}
	if digest != identity.ArtifactSHA256 {
		return errors.New("artifact changed after QA execution")
	}
	return nil
}

func openVerifiedArtifact(path string) (*os.File, os.FileInfo, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("stat artifact: %w", err)
	}
	if err := validateArtifactInfo(pathInfo); err != nil {
		return nil, nil, err
	}
	file, err := openArtifactNoFollow(path)
	if err != nil {
		return nil, nil, errors.New("open artifact without following links")
	}
	fileInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, errors.New("stat opened artifact")
	}
	if err := validateArtifactInfo(fileInfo); err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !os.SameFile(pathInfo, fileInfo) {
		_ = file.Close()
		return nil, nil, errors.New("artifact changed while opening")
	}
	if err := verifyArtifactPath(path, fileInfo); err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	return file, fileInfo, nil
}

func verifyArtifactPath(path string, expected os.FileInfo) error {
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("artifact changed during identity inspection")
	}
	if err := validateArtifactInfo(info); err != nil {
		return err
	}
	if !os.SameFile(info, expected) {
		return errors.New("artifact changed during identity inspection")
	}
	return nil
}

func validateArtifactInfo(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return errors.New("artifact is not a regular file")
	}
	if info.Mode().Perm()&0o111 == 0 {
		return errors.New("artifact is not executable")
	}
	return nil
}

func digestOpenFile(file *os.File) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", errors.New("seek artifact")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", errors.New("hash artifact")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func buildSetting(info *debug.BuildInfo, key string) (string, bool) {
	for _, setting := range info.Settings {
		if setting.Key == key {
			return setting.Value, true
		}
	}
	return "", false
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
