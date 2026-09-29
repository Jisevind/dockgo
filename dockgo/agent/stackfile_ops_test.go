package agent

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"dockgo/engine"
	"dockgo/stacks"
)

// The agent's file operations run on the host that owns the stack files, so
// these tests exercise the factored helpers directly: each WebSocket handler is
// only a decode-and-send wrapper around one of them.

const agentFileComposeOriginal = "services:\n  web:\n    image: nginx\n"

// newAgentFileFixture builds an agent-side stack over a real temp directory
// with one compose file and one .env file. Both files exist because
// ResolveFileTarget resolves symlinks before checking the allow-list, so a
// missing file is reported as missing rather than as a guard rejection.
func newAgentFileFixture(t *testing.T, allowedPaths []string) (*Agent, stacks.Stack, string, string) {
	t.Helper()

	dir := t.TempDir()
	composePath := filepath.Join(dir, "compose.yaml")
	envPath := filepath.Join(dir, ".env")

	writeAgentFile(t, composePath, agentFileComposeOriginal)
	writeAgentFile(t, envPath, "FOO=bar\n")

	stack := stacks.Stack{
		ID:           "stack-1",
		Name:         "demo",
		ProjectName:  "demo",
		Kind:         stacks.KindComposeFiles,
		WorkingDir:   dir,
		ComposeFiles: []string{composePath},
		EnvFiles:     []string{envPath},
		PathMode:     stacks.PathModeHostNative,
	}

	return &Agent{cfg: Config{AllowedPaths: allowedPaths}}, stack, composePath, envPath
}

func writeAgentFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}

func readAgentFile(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	return content
}

// requireAgentFileUnchanged asserts byte equality. A substring assertion would
// miss a rewrite that kept the original text and appended the draft.
func requireAgentFileUnchanged(t *testing.T, path string, want []byte) {
	t.Helper()
	if got := readAgentFile(t, path); !bytes.Equal(got, want) {
		t.Fatalf("content of %s = %q, want it byte-identical to %q", path, got, want)
	}
}

// installAgentFakeDocker puts a stub `docker` first on PATH.
func installAgentFakeDocker(t *testing.T, script string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stub docker relies on a POSIX shell script")
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o700); err != nil {
		t.Fatalf("WriteFile(docker stub) error = %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// writeAgentFakeDocker installs a stub docker whose `compose config` call exits
// with the requested status. When snapshotPath is set the stub copies the
// compose file as it exists at that moment, which is how a test proves
// validation ran against the draft already on disk instead of passing for the
// unrelated reason that nothing was ever written.
func writeAgentFakeDocker(t *testing.T, configOK bool, snapshotPath string) {
	t.Helper()

	exitCode := "1"
	if configOK {
		exitCode = "0"
	}

	snapshot := ""
	if snapshotPath != "" {
		snapshot = "cp compose.yaml \"" + snapshotPath + "\"\n"
	}

	installAgentFakeDocker(t, "#!/bin/sh\n"+
		snapshot+
		"printf '%s' '{\"services\":{}}'\n"+
		"exit "+exitCode+"\n")
}

// writeAgentFakeDockerReplacingDir installs a stub docker that replaces the
// stack's working directory with a regular file while validation runs, so the
// rollback cannot create its temporary file. Permissions cannot force that
// failure: these processes run as root, which ignores write bits.
func writeAgentFakeDockerReplacingDir(t *testing.T, workingDir string) {
	t.Helper()
	installAgentFakeDocker(t, "#!/bin/sh\n"+
		"rm -rf \""+workingDir+"\"\n"+
		"printf 'replaced by the stub docker' > \""+workingDir+"\"\n"+
		"exit 1\n")
}

func requireAgentFileTarget(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s) error = %v", path, err)
	}
	return resolved
}

func TestAgentStackFileTargetRejectsPathOutsideAllowList(t *testing.T) {
	a, stack, composePath, envPath := newAgentFileFixture(t, []string{t.TempDir()})
	composeBefore := readAgentFile(t, composePath)
	envBefore := readAgentFile(t, envPath)

	if _, err := a.agentStackFileTarget(stack, stacks.FileKindCompose, 0); !errors.Is(err, stacks.ErrPathNotAllowed) {
		t.Fatalf("agentStackFileTarget() error = %v, want %v", err, stacks.ErrPathNotAllowed)
	}

	draft := "services:\n  web:\n    image: busybox:1.36\n"
	calls := map[string]func() (any, error){
		"read": func() (any, error) {
			return a.agentStackFileRead(StackFileRequest{Stack: stack, Kind: stacks.FileKindCompose, Index: 0})
		},
		"validate": func() (any, error) {
			return a.agentStackFileValidate(StackFileWriteRequest{Stack: stack, Kind: stacks.FileKindCompose, Index: 0, Content: draft})
		},
		"write": func() (any, error) {
			return a.agentStackFileWrite(context.Background(), StackFileWriteRequest{Stack: stack, Kind: stacks.FileKindCompose, Index: 0, Content: draft})
		},
	}
	for name, call := range calls {
		result, err := call()
		if !errors.Is(err, stacks.ErrPathNotAllowed) {
			t.Fatalf("%s error = %v, want %v", name, err, stacks.ErrPathNotAllowed)
		}
		if result != nil {
			t.Fatalf("%s result = %v, want nil for a rejected target", name, result)
		}
	}

	requireAgentFileUnchanged(t, composePath, composeBefore)
	requireAgentFileUnchanged(t, envPath, envBefore)
}

func TestAgentStackFileTargetResolvesInsideAllowList(t *testing.T) {
	a, stack, composePath, _ := newAgentFileFixture(t, nil)
	a.cfg.AllowedPaths = []string{filepath.Dir(composePath)}

	target, err := a.agentStackFileTarget(stack, stacks.FileKindCompose, 0)
	if err != nil {
		t.Fatalf("agentStackFileTarget() error = %v", err)
	}

	// The guard returns the symlink-resolved path it checked, so compare
	// against the resolved form (t.TempDir may itself sit behind a symlink).
	if want := requireAgentFileTarget(t, composePath); target.Path != want {
		t.Fatalf("target.Path = %q, want %q", target.Path, want)
	}
	if !target.Editable {
		t.Fatal("target.Editable = false, want true for an allow-listed regular file")
	}

	result, err := a.agentStackFileRead(StackFileRequest{Stack: stack, Kind: stacks.FileKindCompose, Index: 0})
	if err != nil {
		t.Fatalf("agentStackFileRead() error = %v", err)
	}
	read, ok := result.(StackFileResult)
	if !ok {
		t.Fatalf("agentStackFileRead() result = %T, want StackFileResult", result)
	}
	if read.Content != agentFileComposeOriginal {
		t.Fatalf("read content = %q, want %q", read.Content, agentFileComposeOriginal)
	}
}

func TestAgentStackFileTargetAllowsEmptyAllowList(t *testing.T) {
	// Empty means no restriction, as GuardPath documents. Treating "no
	// configured paths" as "no permitted paths" would block every agent edit.
	a, stack, composePath, envPath := newAgentFileFixture(t, nil)

	if _, err := a.agentStackFileTarget(stack, stacks.FileKindCompose, 0); err != nil {
		t.Fatalf("agentStackFileTarget() error = %v, want no restriction", err)
	}

	files, err := a.agentStackFileList(StackFileRequest{Stack: stack})
	if err != nil {
		t.Fatalf("agentStackFileList() error = %v", err)
	}
	targets, ok := files.([]stacks.FileTarget)
	if !ok {
		t.Fatalf("agentStackFileList() result = %T, want []stacks.FileTarget", files)
	}
	if len(targets) != 2 {
		t.Fatalf("listed %d targets, want 2 (compose then env)", len(targets))
	}
	wantPaths := []string{requireAgentFileTarget(t, composePath), requireAgentFileTarget(t, envPath)}
	for i, target := range targets {
		if target.Path != wantPaths[i] {
			t.Fatalf("targets[%d].Path = %q, want %q", i, target.Path, wantPaths[i])
		}
		if !target.Editable {
			t.Fatalf("targets[%d].Editable = false, want true with no allow-list", i)
		}
	}

	result, err := a.agentStackFileRead(StackFileRequest{Stack: stack, Kind: stacks.FileKindEnv, Index: 0})
	if err != nil {
		t.Fatalf("agentStackFileRead(env) error = %v", err)
	}
	read, ok := result.(StackFileResult)
	if !ok {
		t.Fatalf("agentStackFileRead(env) result = %T, want StackFileResult", result)
	}
	if read.Content != "FOO=bar\n" {
		t.Fatalf("env content = %q, want %q", read.Content, "FOO=bar\n")
	}
}

func TestAgentStackFileWriteSavesValidContent(t *testing.T) {
	snapshotPath := filepath.Join(t.TempDir(), "at-validation.yaml")
	writeAgentFakeDocker(t, true, snapshotPath)

	a, stack, composePath, _ := newAgentFileFixture(t, nil)

	draft := "services:\n  web:\n    image: busybox:1.36\n"
	result, err := a.agentStackFileWrite(context.Background(),
		StackFileWriteRequest{Stack: stack, Kind: stacks.FileKindCompose, Index: 0, Content: draft})
	if err != nil {
		t.Fatalf("agentStackFileWrite() error = %v", err)
	}

	payload, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("agentStackFileWrite() result = %T, want the {\"target\": ...} payload the local save returns", result)
	}
	target, ok := payload["target"].(stacks.FileTarget)
	if !ok {
		t.Fatalf("payload target = %T, want stacks.FileTarget", payload["target"])
	}
	if want := requireAgentFileTarget(t, composePath); target.Path != want {
		t.Fatalf("target.Path = %q, want %q", target.Path, want)
	}

	if got := string(readAgentFile(t, composePath)); got != draft {
		t.Fatalf("saved content = %q, want the draft %q", got, draft)
	}
	if got := string(readAgentFile(t, snapshotPath)); got != draft {
		t.Fatalf("content at validation time = %q, want the draft already on disk %q", got, draft)
	}
}

func TestAgentStackFileWriteRejectsOversizeContent(t *testing.T) {
	a, stack, composePath, _ := newAgentFileFixture(t, nil)
	before := readAgentFile(t, composePath)

	// Comment-only YAML is syntactically valid, so only the size cap can
	// reject this draft.
	oversize := strings.Repeat("#", stacks.MaxEditableFileBytes+1)
	if _, err := a.agentStackFileWrite(context.Background(),
		StackFileWriteRequest{Stack: stack, Kind: stacks.FileKindCompose, Index: 0, Content: oversize}); !errors.Is(err, stacks.ErrFileTooLarge) {
		t.Fatalf("agentStackFileWrite() error = %v, want %v", err, stacks.ErrFileTooLarge)
	}

	requireAgentFileUnchanged(t, composePath, before)
}

func TestAgentStackFileWriteRejectsOversizeContentBeforeSyntax(t *testing.T) {
	a, stack, composePath, _ := newAgentFileFixture(t, nil)
	before := readAgentFile(t, composePath)

	// Both refusals apply to this draft: it is over the cap AND unparseable.
	// The cap must win, because that is the server's first refusal, so a client
	// that tells "too large" from "syntax error" sees one answer on both hosts.
	draft := strings.Repeat("#", stacks.MaxEditableFileBytes+1) + "\nservices: [\n"
	_, err := a.agentStackFileWrite(context.Background(),
		StackFileWriteRequest{Stack: stack, Kind: stacks.FileKindCompose, Index: 0, Content: draft})
	if !errors.Is(err, stacks.ErrFileTooLarge) {
		t.Fatalf("agentStackFileWrite() error = %v, want %v (the cap must be checked before syntax)", err, stacks.ErrFileTooLarge)
	}
	if errors.Is(err, errStackFileInvalidSyntax) {
		t.Fatalf("agentStackFileWrite() error = %v, want the cap refusal, not the syntax refusal", err)
	}

	requireAgentFileUnchanged(t, composePath, before)
}

func TestAgentStackFileWriteRejectsInvalidSyntaxWithoutWriting(t *testing.T) {
	a, stack, composePath, _ := newAgentFileFixture(t, nil)
	before := readAgentFile(t, composePath)

	draft := "services:\n  web: [\n"
	_, err := a.agentStackFileWrite(context.Background(),
		StackFileWriteRequest{Stack: stack, Kind: stacks.FileKindCompose, Index: 0, Content: draft})
	if !errors.Is(err, errStackFileInvalidSyntax) {
		t.Fatalf("agentStackFileWrite() error = %v, want %v", err, errStackFileInvalidSyntax)
	}

	requireAgentFileUnchanged(t, composePath, before)
}

func TestAgentStackFileWriteRestoresPreviousContentWhenValidationFails(t *testing.T) {
	snapshotPath := filepath.Join(t.TempDir(), "at-validation.yaml")
	writeAgentFakeDocker(t, false, snapshotPath)

	a, stack, composePath, _ := newAgentFileFixture(t, nil)
	before := readAgentFile(t, composePath)

	draft := "services:\n  web:\n    image: busybox:1.36\n"
	_, err := a.agentStackFileWrite(context.Background(),
		StackFileWriteRequest{Stack: stack, Kind: stacks.FileKindCompose, Index: 0, Content: draft})
	if !errors.Is(err, errStackFileValidationFailed) {
		t.Fatalf("agentStackFileWrite() error = %v, want %v", err, errStackFileValidationFailed)
	}
	if errors.Is(err, errStackFileRollbackFailed) {
		t.Fatalf("agentStackFileWrite() error = %v, want a restored rollback, not a failed one", err)
	}

	// The draft must have reached the disk before validation ran, otherwise
	// this test would pass because the save was refused earlier.
	if got := string(readAgentFile(t, snapshotPath)); got != draft {
		t.Fatalf("content at validation time = %q, want the draft %q (the write must precede validation)", got, draft)
	}
	requireAgentFileUnchanged(t, composePath, before)
}

// TestAgentStackFileWriteWaitsForTheProjectLock pins the lock that keeps a save
// from interleaving with a deploy of the same project. A save that ignored the
// lock would complete while the test still holds it.
func TestAgentStackFileWriteWaitsForTheProjectLock(t *testing.T) {
	writeAgentFakeDocker(t, true, "")
	a, stack, composePath, _ := newAgentFileFixture(t, nil)
	before := readAgentFile(t, composePath)

	unlock := engine.LockProject(stackProjectName(stack))
	released := false
	release := func() {
		if !released {
			released = true
			unlock()
		}
	}
	defer release()

	draft := "services:\n  web:\n    image: busybox:1.36\n"
	done := make(chan error, 1)
	go func() {
		_, err := a.agentStackFileWrite(context.Background(),
			StackFileWriteRequest{Stack: stack, Kind: stacks.FileKindCompose, Index: 0, Content: draft})
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("save completed while the project lock was held (err = %v)", err)
	case <-time.After(200 * time.Millisecond):
	}
	requireAgentFileUnchanged(t, composePath, before)

	release()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("agentStackFileWrite() error = %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("save did not complete after the project lock was released")
	}

	if got := string(readAgentFile(t, composePath)); got != draft {
		t.Fatalf("saved content = %q, want the draft %q", got, draft)
	}
}

// TestAgentStackFileWriteBacksUpAfterTakingTheProjectLock pins the ordering
// that makes the backup safe: a concurrent save that lands between a pre-lock
// backup read and the lock would be undone by the restore. Here the concurrent
// content is written while the save waits for the lock, so the content restored
// after the failed validation tells which of the two the save captured.
func TestAgentStackFileWriteBacksUpAfterTakingTheProjectLock(t *testing.T) {
	writeAgentFakeDocker(t, false, "") // validation always fails, so the backup is restored
	a, stack, composePath, _ := newAgentFileFixture(t, nil)

	unlock := engine.LockProject(stackProjectName(stack))
	released := false
	release := func() {
		if !released {
			released = true
			unlock()
		}
	}
	defer release()

	draft := "services:\n  web:\n    image: busybox:1.36\n"
	done := make(chan error, 1)
	go func() {
		_, err := a.agentStackFileWrite(context.Background(),
			StackFileWriteRequest{Stack: stack, Kind: stacks.FileKindCompose, Index: 0, Content: draft})
		done <- err
	}()

	// By now a save that backed up before the lock has already read the
	// original content, and one that backs up inside the lock has read nothing.
	select {
	case err := <-done:
		t.Fatalf("save completed while the project lock was held (err = %v)", err)
	case <-time.After(200 * time.Millisecond):
	}

	concurrent := "services:\n  web:\n    image: concurrent\n"
	writeAgentFile(t, composePath, concurrent)
	release()

	select {
	case err := <-done:
		if !errors.Is(err, errStackFileValidationFailed) {
			t.Fatalf("agentStackFileWrite() error = %v, want %v", err, errStackFileValidationFailed)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("save did not complete after the project lock was released")
	}

	if got := string(readAgentFile(t, composePath)); got != concurrent {
		t.Fatalf("restored content = %q, want the concurrently written %q (the backup must be read after the lock)", got, concurrent)
	}
}

func TestAgentStackFileWriteReportsFailedRollbackDistinctly(t *testing.T) {
	a, stack, composePath, _ := newAgentFileFixture(t, nil)
	writeAgentFakeDockerReplacingDir(t, stack.WorkingDir)

	draft := "services:\n  web:\n    image: busybox:1.36\n"
	_, err := a.agentStackFileWrite(context.Background(),
		StackFileWriteRequest{Stack: stack, Kind: stacks.FileKindCompose, Index: 0, Content: draft})
	if !errors.Is(err, errStackFileRollbackFailed) {
		t.Fatalf("agentStackFileWrite() error = %v, want %v", err, errStackFileRollbackFailed)
	}
	if errors.Is(err, errStackFileValidationFailed) {
		t.Fatalf("agentStackFileWrite() error = %v, want a distinct failed-rollback error", err)
	}

	// Guard the scenario itself: if the stub never replaced the directory, the
	// rollback would have succeeded and the assertions above would be testing
	// something else.
	if info, statErr := os.Stat(stack.WorkingDir); statErr != nil || info.IsDir() {
		t.Fatalf("working dir %s was not replaced by the stub docker (err=%v): the rollback failure was not exercised", stack.WorkingDir, statErr)
	}
	if _, statErr := os.Stat(composePath); statErr == nil {
		t.Fatalf("%s still exists, want the un-restorable draft", composePath)
	}
}

func TestAgentStackFileOperationsRejectGitKindStack(t *testing.T) {
	a, stack, composePath, _ := newAgentFileFixture(t, nil)
	before := readAgentFile(t, composePath)

	gitKind := stack
	gitKind.Kind = stacks.KindGitRepo

	gitSource := stack
	gitSource.GitSource = &stacks.GitSource{RepoURL: "https://example.com/repo.git"}

	for name, candidate := range map[string]stacks.Stack{"kind": gitKind, "git_source": gitSource} {
		calls := map[string]func() (any, error){
			"list": func() (any, error) {
				return a.agentStackFileList(StackFileRequest{Stack: candidate})
			},
			"read": func() (any, error) {
				return a.agentStackFileRead(StackFileRequest{Stack: candidate, Kind: stacks.FileKindCompose, Index: 0})
			},
			"validate": func() (any, error) {
				return a.agentStackFileValidate(StackFileWriteRequest{Stack: candidate, Kind: stacks.FileKindCompose, Index: 0, Content: agentFileComposeOriginal})
			},
			"write": func() (any, error) {
				return a.agentStackFileWrite(context.Background(), StackFileWriteRequest{Stack: candidate, Kind: stacks.FileKindCompose, Index: 0, Content: agentFileComposeOriginal})
			},
		}
		for op, call := range calls {
			result, err := call()
			if !errors.Is(err, errGitStackUnsupported) {
				t.Fatalf("%s %s error = %v, want %v", name, op, err, errGitStackUnsupported)
			}
			// The wire carries only the text, and the server matches on it.
			if err.Error() != "git-kind stacks are not supported on remote agents" {
				t.Fatalf("%s %s error text = %q, want the message the other agent stack ops return", name, op, err.Error())
			}
			if result != nil {
				t.Fatalf("%s %s result = %v, want nil", name, op, result)
			}
		}
	}

	requireAgentFileUnchanged(t, composePath, before)
}

func TestAgentStackFileValidateIsKindAware(t *testing.T) {
	a, stack, _, _ := newAgentFileFixture(t, nil)

	tests := []struct {
		name      string
		kind      string
		content   string
		wantValid bool
	}{
		{name: "compose draft as compose", kind: stacks.FileKindCompose, content: agentFileComposeOriginal, wantValid: true},
		// A compose document is not a .env file. If the kind were ignored and
		// the draft always checked as compose, this would report valid.
		{name: "compose draft as env", kind: stacks.FileKindEnv, content: agentFileComposeOriginal, wantValid: false},
		{name: "env draft as env", kind: stacks.FileKindEnv, content: "FOO=bar\n", wantValid: true},
		{name: "broken yaml as compose", kind: stacks.FileKindCompose, content: "services:\n  web: [\n", wantValid: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := a.agentStackFileValidate(StackFileWriteRequest{Stack: stack, Kind: tc.kind, Index: 0, Content: tc.content})
			if err != nil {
				t.Fatalf("agentStackFileValidate() error = %v", err)
			}
			syntax, ok := result.(stacks.SyntaxResult)
			if !ok {
				t.Fatalf("agentStackFileValidate() result = %T, want stacks.SyntaxResult", result)
			}
			if syntax.Valid != tc.wantValid {
				t.Fatalf("syntax.Valid = %v, want %v (errors=%v)", syntax.Valid, tc.wantValid, syntax.Errors)
			}
		})
	}
}
