package stacks

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCreateEnvFile(t *testing.T) {
	root := t.TempDir()
	stack := Stack{
		WorkingDir: root,
		PathMode:   PathModeHostNative,
	}

	stored, err := CreateEnvFile(stack, ".env", []string{root})
	if err != nil {
		t.Fatalf("CreateEnvFile() error = %v", err)
	}
	if want := filepath.Join(root, ".env"); stored != want {
		t.Fatalf("stored path = %q, want %q", stored, want)
	}
	info, err := os.Stat(filepath.Join(root, ".env"))
	if err != nil {
		t.Fatalf("created file stat error = %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("created file size = %d, want 0", info.Size())
	}

	// An empty file that is not registered yet is adopted so a retry after a
	// failed registration succeeds.
	if got, err := CreateEnvFile(stack, ".env", []string{root}); err != nil || got != stored {
		t.Fatalf("retry CreateEnvFile() = %q, %v; want %q, nil", got, err, stored)
	}

	// A registered file is never reused.
	registered := stack
	registered.EnvFiles = []string{stored}
	if _, err := CreateEnvFile(registered, ".env", []string{root}); err == nil {
		t.Fatal("CreateEnvFile() reused a registered file")
	}

	// A non-empty file is never adopted.
	if err := os.WriteFile(filepath.Join(root, "data.env"), []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateEnvFile(stack, "data.env", []string{root}); err == nil {
		t.Fatal("CreateEnvFile() overwrote a non-empty file")
	}
}

func TestCreateEnvFileRejectsPathTraversal(t *testing.T) {
	root := t.TempDir()
	stack := Stack{WorkingDir: root, PathMode: PathModeHostNative}

	for _, name := range []string{"", ".", "..", "../escape.env", "nested/.env", `nested\.env`} {
		if _, err := CreateEnvFile(stack, name, []string{root}); err == nil {
			t.Errorf("CreateEnvFile(%q) error = nil, want rejection", name)
		}
	}

	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "escape.env")); err == nil {
		t.Fatal("CreateEnvFile() created a file outside the working directory")
	}
}

func TestCreateEnvFileRespectsAllowedPaths(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	stack := Stack{WorkingDir: other, PathMode: PathModeHostNative}

	if _, err := CreateEnvFile(stack, ".env", []string{root}); err == nil {
		t.Fatal("CreateEnvFile() ignored the allow-list")
	}
	created := filepath.Join(other, ".env")
	if _, err := os.Stat(created); err == nil {
		t.Fatalf("CreateEnvFile() created %s despite the allow-list", created)
	}
}

func TestCreateEnvFileMappedStack(t *testing.T) {
	runtimeRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(runtimeRoot, "app"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	stack := Stack{
		WorkingDir: "/host/compose/app",
		PathMode:   PathModeMapped,
		PathMappings: []PathMapping{
			{HostPath: "/host/compose", ContainerPath: runtimeRoot},
		},
	}

	stored, err := CreateEnvFile(stack, ".env.local", []string{runtimeRoot})
	if err != nil {
		t.Fatalf("CreateEnvFile() error = %v", err)
	}
	if want := "/host/compose/app/.env.local"; stored != want {
		t.Fatalf("stored path = %q, want %q", stored, want)
	}
	if _, err := os.Stat(filepath.Join(runtimeRoot, "app", ".env.local")); err != nil {
		t.Fatalf("mapped file was not created: %v", err)
	}
}
