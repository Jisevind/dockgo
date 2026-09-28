package stacks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGuardPathAllowList is the regression suite for ALLOWED_COMPOSE_PATHS.
// The bug it pins: allow-list entries are documented in HOST terms
// (/home/user/docker) while the process may see the same tree mapped
// (/compose). Comparing the two forms without translating made valid compose
// directories get rejected.
func TestGuardPathAllowList(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "stack")
	outside := t.TempDir()

	for _, dir := range []string{inside, outside} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll(%s) error = %v", dir, err)
		}
	}
	target := filepath.Join(inside, "compose.yaml")
	if err := os.WriteFile(target, []byte("services: {}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	outsideTarget := filepath.Join(outside, "compose.yaml")
	if err := os.WriteFile(outsideTarget, []byte("services: {}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	sibling := root + "2"
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", sibling, err)
	}

	tests := []struct {
		name    string
		path    string
		allowed []string
		wantErr bool
	}{
		{name: "inside allow-list", path: target, allowed: []string{root}},
		{name: "outside allow-list", path: outsideTarget, allowed: []string{root}, wantErr: true},
		{name: "sibling prefix is not a match", path: target, allowed: []string{sibling}, wantErr: true},
		{name: "empty allow-list disables the check", path: outsideTarget, allowed: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := GuardPath(tc.path, tc.allowed)
			if tc.wantErr && err == nil {
				t.Fatal("GuardPath() error = nil, want rejection")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("GuardPath() error = %v, want nil", err)
			}
			if tc.wantErr && !errors.Is(err, ErrPathNotAllowed) {
				t.Fatalf("GuardPath() error = %v, want ErrPathNotAllowed", err)
			}
		})
	}
}

// TestGuardPathTranslatesAllowListEntries covers the deployment shape where the
// allow-list is configured in host terms but the process sees mapped paths.
func TestGuardPathTranslatesAllowListEntries(t *testing.T) {
	root := t.TempDir()
	stackDir := filepath.Join(root, "crawl4ai")
	if err := os.MkdirAll(stackDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	target := filepath.Join(stackDir, "compose.yaml")
	if err := os.WriteFile(target, []byte("services: {}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	hostForm := "/host/docker"
	t.Setenv("COMPOSE_PATH_MAPPING", hostForm+":"+root)

	got, err := GuardPath(target, []string{hostForm})
	if err != nil {
		t.Fatalf("GuardPath() error = %v, want nil (host-style allow-list entry must translate)", err)
	}
	if got != target {
		t.Fatalf("GuardPath() = %q, want %q", got, target)
	}
}

func TestGuardPathRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "allowed")
	if err := os.MkdirAll(allowed, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	secretDir := t.TempDir()
	secret := filepath.Join(secretDir, "secret.yaml")
	if err := os.WriteFile(secret, []byte("services: {}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	link := filepath.Join(allowed, "escape.yaml")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if _, err := GuardPath(link, []string{root}); err == nil {
		t.Fatal("GuardPath() error = nil, want rejection for symlink escaping the allow-list")
	}
}

func TestGuardPathRequiresExistingAbsolutePath(t *testing.T) {
	if _, err := GuardPath(filepath.Join(t.TempDir(), "missing.yaml"), nil); err == nil {
		t.Fatal("GuardPath() error = nil, want error for missing path")
	}
	if _, err := GuardPath("relative/path.yaml", nil); err == nil {
		t.Fatal("GuardPath() error = nil, want error for relative path")
	}
	if _, err := GuardPath("   ", nil); err == nil {
		t.Fatal("GuardPath() error = nil, want error for blank path")
	}
}

func TestGuardPathErrorNamesTheAllowList(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "compose.yaml")
	if err := os.WriteFile(target, []byte("services: {}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// A base that cannot be resolved must be skipped, and the remaining
	// unresolvable case must still fail closed with a useful message.
	_, err := GuardPath(target, []string{filepath.Join(root, "does-not-exist")})
	if err == nil {
		t.Fatal("GuardPath() error = nil, want rejection")
	}
	if !strings.Contains(err.Error(), filepath.Join(root, "does-not-exist")) {
		t.Fatalf("error = %q, want it to name the allow-list entries", err.Error())
	}
}
