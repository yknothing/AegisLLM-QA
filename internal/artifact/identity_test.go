package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInspectBindsDigestBuildInfoToolchainAndAnchoredVersion(t *testing.T) {
	binary, sourceSHA := buildFixture(t, fixtureOptions{})
	digest := fileDigest(t, binary)

	identity, err := Inspect(context.Background(), binary, Expected{
		SourceSHA:      sourceSHA,
		ArtifactSHA256: digest,
		Toolchain:      runtime.Version(),
	})
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if identity.SourceSHA != sourceSHA || identity.ArtifactSHA256 != digest {
		t.Fatalf("identity = %#v", identity)
	}
	if identity.Toolchain != runtime.Version() || identity.Version != "qa-fixture" {
		t.Fatalf("identity = %#v", identity)
	}
	if identity.Modified {
		t.Fatal("clean fixture reported modified")
	}
}

func TestInspectRejectsExternalDigestMismatch(t *testing.T) {
	binary, sourceSHA := buildFixture(t, fixtureOptions{})
	_, err := Inspect(context.Background(), binary, Expected{
		SourceSHA:      sourceSHA,
		ArtifactSHA256: strings.Repeat("f", 64),
		Toolchain:      runtime.Version(),
	})
	if err == nil || !strings.Contains(err.Error(), "artifact_sha256") {
		t.Fatalf("Inspect() error = %v", err)
	}
}

func TestInspectRejectsSymlinkBeforeExecutingArtifact(t *testing.T) {
	binary, sourceSHA := buildFixture(t, fixtureOptions{})
	link := filepath.Join(t.TempDir(), "aegis-link")
	if err := os.Symlink(binary, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	_, err := Inspect(context.Background(), link, Expected{
		SourceSHA:      sourceSHA,
		ArtifactSHA256: fileDigest(t, binary),
		Toolchain:      runtime.Version(),
	})
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("Inspect() error = %v, want symlink rejection", err)
	}
}

func TestInspectRejectsModifiedBuildAndToolchainMismatch(t *testing.T) {
	t.Run("modified", func(t *testing.T) {
		binary, sourceSHA := buildFixture(t, fixtureOptions{dirty: true})
		_, err := Inspect(context.Background(), binary, Expected{
			SourceSHA: sourceSHA, ArtifactSHA256: fileDigest(t, binary), Toolchain: runtime.Version(),
		})
		if err == nil || !strings.Contains(err.Error(), "vcs.modified") {
			t.Fatalf("Inspect() error = %v", err)
		}
	})

	t.Run("toolchain", func(t *testing.T) {
		binary, sourceSHA := buildFixture(t, fixtureOptions{})
		_, err := Inspect(context.Background(), binary, Expected{
			SourceSHA: sourceSHA, ArtifactSHA256: fileDigest(t, binary), Toolchain: "go0.0.0",
		})
		if err == nil || !strings.Contains(err.Error(), "toolchain") {
			t.Fatalf("Inspect() error = %v", err)
		}
	})
}

func TestInspectRejectsUnanchoredVersionOutput(t *testing.T) {
	binary, sourceSHA := buildFixture(t, fixtureOptions{versionSuffix: "\nuntrusted suffix"})
	_, err := Inspect(context.Background(), binary, Expected{
		SourceSHA: sourceSHA, ArtifactSHA256: fileDigest(t, binary), Toolchain: runtime.Version(),
	})
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("Inspect() error = %v", err)
	}
}

func TestVerifyUnchangedDetectsPostRunMutation(t *testing.T) {
	binary, sourceSHA := buildFixture(t, fixtureOptions{})
	identity, err := Inspect(context.Background(), binary, Expected{
		SourceSHA: sourceSHA, ArtifactSHA256: fileDigest(t, binary), Toolchain: runtime.Version(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyUnchanged(binary, identity); err != nil {
		t.Fatalf("VerifyUnchanged() clean error = %v", err)
	}
	if err := os.WriteFile(binary, []byte("mutated"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := VerifyUnchanged(binary, identity); err == nil {
		t.Fatal("VerifyUnchanged() accepted mutated SUT")
	}
}

type fixtureOptions struct {
	dirty         bool
	versionSuffix string
}

func buildFixture(t *testing.T, opts fixtureOptions) (string, string) {
	t.Helper()
	dir := t.TempDir()
	mainSource := fmt.Sprintf(`package main
import (
    "fmt"
    "os"
)
var commit = "none"
func main() {
    if len(os.Args) == 2 && os.Args[1] == "--version" {
        fmt.Printf("aegis qa-fixture (commit: %%s, built: 2026-07-16T00:00:00Z)\n%s", commit)
        return
    }
}
`, strings.ReplaceAll(opts.versionSuffix, "\n", `\n`))
	writeFile(t, filepath.Join(dir, "go.mod"), "module fixture.invalid/aegis\n\ngo 1.22.4\n")
	writeFile(t, filepath.Join(dir, "main.go"), mainSource)
	run(t, dir, "git", "init", "-q")
	run(t, dir, "git", "config", "user.email", "qa@example.invalid")
	run(t, dir, "git", "config", "user.name", "QA Fixture")
	run(t, dir, "git", "add", "go.mod", "main.go")
	run(t, dir, "git", "commit", "-qm", "fixture")
	sourceSHA := strings.TrimSpace(run(t, dir, "git", "rev-parse", "HEAD"))
	if opts.dirty {
		if err := os.WriteFile(filepath.Join(dir, "dirty.txt"), []byte("untracked does not mark build info"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainSource+"\n// tracked modification\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(t.TempDir(), "aegis")
	run(t, dir, "go", "build", "-ldflags", "-X main.commit="+sourceSHA, "-o", binary, ".")
	return binary, sourceSHA
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func run(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}
