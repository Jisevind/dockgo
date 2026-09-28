package engine

import (
	"os"
	"path/filepath"
	"testing"
)

// TestValidateWorkingDirTranslatesHostStyleAllowList pins the fix for the
// inconsistency this work started from: the candidate was translated but the
// allow-list was not, so a host-style entry never matched a mapped path.
func TestValidateWorkingDirTranslatesHostStyleAllowList(t *testing.T) {
	root := t.TempDir()
	hostForm := "/host/docker"
	t.Setenv("COMPOSE_PATH_MAPPING", hostForm+":"+root)

	got, err := validateWorkingDir(root, []string{hostForm})
	if err != nil {
		t.Fatalf("validateWorkingDir() error = %v, want nil", err)
	}
	if got != root {
		t.Fatalf("validateWorkingDir() = %q, want %q", got, root)
	}
}

func TestValidateWorkingDirRejectsOutsideAllowList(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "stack")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	outside := t.TempDir()

	if _, err := validateWorkingDir(outside, []string{root}); err == nil {
		t.Fatal("validateWorkingDir() error = nil, want rejection")
	}
	if _, err := validateWorkingDir(inside, []string{root}); err != nil {
		t.Fatalf("validateWorkingDir() error = %v, want nil", err)
	}
}

func TestValidateWorkingDirRequiresDirectory(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "compose.yaml")
	if err := os.WriteFile(file, []byte("services: {}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if _, err := validateWorkingDir(file, nil); err == nil {
		t.Fatal("validateWorkingDir() error = nil, want error for a non-directory")
	}
}

func TestValidateWorkingDirEmptyAllowListIsPermissive(t *testing.T) {
	root := t.TempDir()
	if _, err := validateWorkingDir(root, nil); err != nil {
		t.Fatalf("validateWorkingDir() error = %v, want nil with no allow-list", err)
	}
}
