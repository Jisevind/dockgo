package stacks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// editableStack is a host-native stack whose compose and env files live
// directly in dir, so the target tests exercise resolution without any path
// mapping in the way.
func editableStack(dir string) Stack {
	return Stack{
		ID:           "stack-1",
		Name:         "stack-1",
		WorkingDir:   dir,
		ComposeFiles: []string{filepath.Join(dir, "compose.yaml")},
		EnvFiles:     []string{filepath.Join(dir, ".env")},
	}
}

func TestFileTargetsListsComposeThenEnv(t *testing.T) {
	dir := t.TempDir()
	stack := editableStack(dir)

	writeFile(t, stack.ComposeFiles[0], "services: {}\n")
	writeFile(t, stack.EnvFiles[0], "FOO=bar\n")

	targets := FileTargets(stack, []string{dir})
	if len(targets) != 2 {
		t.Fatalf("FileTargets() length = %d, want 2", len(targets))
	}
	if targets[0].Kind != FileKindCompose || targets[0].Index != 0 {
		t.Fatalf("FileTargets()[0] = %+v, want compose index 0", targets[0])
	}
	if targets[1].Kind != FileKindEnv || targets[1].Index != 0 {
		t.Fatalf("FileTargets()[1] = %+v, want env index 0", targets[1])
	}
	for i, target := range targets {
		if !target.Exists || !target.Editable {
			t.Fatalf("FileTargets()[%d] = %+v, want an existing editable target", i, target)
		}
	}
}

func TestResolveFileTargetAcceptsEditableFile(t *testing.T) {
	dir := t.TempDir()
	stack := editableStack(dir)
	writeFile(t, stack.ComposeFiles[0], "services: {}\n")

	target, err := ResolveFileTarget(stack, FileKindCompose, 0, []string{dir})
	if err != nil {
		t.Fatalf("ResolveFileTarget() error = %v, want nil", err)
	}

	if target.Kind != FileKindCompose || target.Index != 0 {
		t.Fatalf("ResolveFileTarget() = %+v, want compose index 0", target)
	}
	if target.Label != "compose.yaml" {
		t.Fatalf("ResolveFileTarget().Label = %q, want %q", target.Label, "compose.yaml")
	}
	if target.Size != int64(len("services: {}\n")) {
		t.Fatalf("ResolveFileTarget().Size = %d, want %d", target.Size, len("services: {}\n"))
	}
	if !target.Exists || !target.Editable {
		t.Fatalf("ResolveFileTarget() = %+v, want exists and editable", target)
	}
	if filepath.Base(target.Path) != "compose.yaml" {
		t.Fatalf("ResolveFileTarget().Path = %q, want the resolved compose path", target.Path)
	}
}

// TestResolveFileTargetRejections pins the error taxonomy the transport layers
// map onto statuses. The two address errors carry no sentinel on purpose: they
// are client mistakes that must stay 400 rather than being reported as a
// missing or unreadable file.
func TestResolveFileTargetRejections(t *testing.T) {
	dir := t.TempDir()
	outsideDir := t.TempDir()

	stack := editableStack(dir)
	writeFile(t, stack.ComposeFiles[0], "services: {}\n")

	missing := editableStack(dir)
	missing.ComposeFiles = []string{filepath.Join(dir, "missing.yaml")}

	noEnvFiles := editableStack(dir)
	noEnvFiles.EnvFiles = nil

	notRegular := editableStack(dir)
	notRegular.ComposeFiles = []string{filepath.Join(dir, "a-directory")}
	if err := os.Mkdir(notRegular.ComposeFiles[0], 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}

	tooLarge := editableStack(dir)
	tooLarge.ComposeFiles = []string{filepath.Join(dir, "over.yaml")}
	if err := os.WriteFile(tooLarge.ComposeFiles[0], make([]byte, MaxEditableFileBytes+1), 0o600); err != nil {
		t.Fatalf("WriteFile(over) error = %v", err)
	}

	outside := editableStack(outsideDir)
	writeFile(t, outside.ComposeFiles[0], "services: {}\n")

	tests := []struct {
		name         string
		stack        Stack
		kind         string
		index        int
		allowed      []string
		wantSentinel error
		wantMessage  string
	}{
		{
			name:        "index out of range",
			stack:       stack,
			kind:        FileKindCompose,
			index:       9,
			allowed:     []string{dir},
			wantMessage: "compose index 9 is out of range",
		},
		{
			name:        "env index out of range",
			stack:       noEnvFiles,
			kind:        FileKindEnv,
			index:       0,
			allowed:     []string{dir},
			wantMessage: "env index 0 is out of range",
		},
		{
			name:        "unknown kind",
			stack:       stack,
			kind:        "nonsense",
			index:       0,
			allowed:     []string{dir},
			wantMessage: "unsupported file kind: nonsense",
		},
		{
			name:         "missing file",
			stack:        missing,
			kind:         FileKindCompose,
			index:        0,
			allowed:      []string{dir},
			wantSentinel: ErrFileMissing,
		},
		{
			name:         "directory in place of a file",
			stack:        notRegular,
			kind:         FileKindCompose,
			index:        0,
			allowed:      []string{dir},
			wantSentinel: ErrFileNotRegular,
		},
		{
			name:         "file over the cap",
			stack:        tooLarge,
			kind:         FileKindCompose,
			index:        0,
			allowed:      []string{dir},
			wantSentinel: ErrFileTooLarge,
		},
		{
			name:         "file outside the allow-list",
			stack:        outside,
			kind:         FileKindCompose,
			index:        0,
			allowed:      []string{dir},
			wantSentinel: ErrPathNotAllowed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target, err := ResolveFileTarget(tc.stack, tc.kind, tc.index, tc.allowed)
			if err == nil {
				t.Fatalf("ResolveFileTarget() error = nil, want a failure")
			}

			if tc.wantSentinel != nil {
				if !errors.Is(err, tc.wantSentinel) {
					t.Fatalf("ResolveFileTarget() error = %v, want %v", err, tc.wantSentinel)
				}
			} else {
				for _, sentinel := range []error{ErrFileMissing, ErrFileNotRegular, ErrFileTooLarge, ErrPathNotAllowed} {
					if errors.Is(err, sentinel) {
						t.Fatalf("ResolveFileTarget() error = %v, must not match %v", err, sentinel)
					}
				}
			}

			if !strings.Contains(err.Error(), tc.wantMessage) {
				t.Fatalf("ResolveFileTarget() error = %v, want it to contain %q", err, tc.wantMessage)
			}
			if target != (FileTarget{}) {
				t.Fatalf("ResolveFileTarget() target = %+v, want the zero target on failure", target)
			}
		})
	}
}

// TestReadEditableFileRejectsOversizedFile is the Phase 1 primitive test,
// relocated with the primitive it exercises; its assertions are unchanged.
func TestReadEditableFileRejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()

	exact := filepath.Join(dir, "exact.yaml")
	if err := os.WriteFile(exact, make([]byte, MaxEditableFileBytes), 0o600); err != nil {
		t.Fatalf("WriteFile(exact) error = %v", err)
	}
	got, err := ReadEditableFile(exact)
	if err != nil {
		t.Fatalf("ReadEditableFile(exact) error = %v, want nil", err)
	}
	if len(got) != MaxEditableFileBytes {
		t.Fatalf("ReadEditableFile(exact) length = %d, want %d", len(got), MaxEditableFileBytes)
	}

	over := filepath.Join(dir, "over.yaml")
	if err := os.WriteFile(over, make([]byte, MaxEditableFileBytes+1), 0o600); err != nil {
		t.Fatalf("WriteFile(over) error = %v", err)
	}
	if _, err := ReadEditableFile(over); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("ReadEditableFile(over) error = %v, want ErrFileTooLarge", err)
	}
}

func TestWriteFileAtomicReplacesContentPreservingMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "compose.yaml")
	writeFile(t, path, "services: {}\n")
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}

	replacement := "services:\n  web:\n    image: nginx\n"
	if err := WriteFileAtomic(path, replacement); err != nil {
		t.Fatalf("WriteFileAtomic() error = %v, want nil", err)
	}

	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(saved) != replacement {
		t.Fatalf("content = %q, want %q", saved, replacement)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %o, want 640 (the existing mode must be preserved)", info.Mode().Perm())
	}

	leftovers, err := filepath.Glob(filepath.Join(dir, "*.tmp-*"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %v, want none after a successful write", leftovers)
	}
}

func TestWriteFileAtomicKeepsOriginalWhenDirectoryIsNotWritable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "compose.yaml")
	original := "services: {}\n"
	writeFile(t, path, original)

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Errorf("Chmod(restore) error = %v", err)
		}
	})

	// Root and Windows ignore directory permission bits, so probe the
	// precondition instead of assuming the directory is unwritable.
	if probe, err := os.CreateTemp(dir, "probe-*"); err == nil {
		_ = probe.Close()
		_ = os.Remove(probe.Name())
		t.Skip("directory permissions do not prevent writes for this user")
	}

	if err := WriteFileAtomic(path, "services:\n  web:\n    image: nginx\n"); err == nil {
		t.Fatalf("WriteFileAtomic() error = nil, want a failure on an unwritable directory")
	}

	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(saved) != original {
		t.Fatalf("content = %q, want the original %q (a failed write must not touch the file)", saved, original)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "compose.yaml" {
		t.Fatalf("directory holds %v, want only compose.yaml (a failed write must clean up)", entries)
	}
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}
