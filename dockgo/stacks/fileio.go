package stacks

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// MaxEditableFileBytes caps editor reads and writes so a huge or unexpected
// file cannot be pulled through the API. The server and the agent share this
// one definition.
const MaxEditableFileBytes = 1 << 20

// Sentinel errors let callers map a failed target resolution onto a transport
// status (403 outside the allow-list or not a regular file, 413 too large, 404
// missing) instead of collapsing every failure into 400.
var (
	ErrFileMissing    = errors.New("file does not exist")
	ErrFileTooLarge   = errors.New("file exceeds the editable size limit")
	ErrFileNotRegular = errors.New("file is not a regular file")
)

// FileTarget is one editable file of a stack, addressed by kind and index.
type FileTarget struct {
	Kind     string `json:"kind"`
	Index    int    `json:"index"`
	Label    string `json:"label"`
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Exists   bool   `json:"exists"`
	Editable bool   `json:"editable"`
}

// FileTargets lists the editable files of a stack: compose files first, then
// env files. The order defines the index space the client uses. Stored paths
// are mapped into the process's filesystem space and guarded like the
// read/write path, and targets that fail the guard are reported but not marked
// editable.
func FileTargets(stack Stack, allowedPaths []string) []FileTarget {
	targets := make([]FileTarget, 0, len(stack.ComposeFiles)+len(stack.EnvFiles))

	for i, path := range stack.ComposeFiles {
		targets = append(targets, newFileTarget(stack, FileKindCompose, i, path, allowedPaths))
	}
	for i, path := range stack.EnvFiles {
		targets = append(targets, newFileTarget(stack, FileKindEnv, i, path, allowedPaths))
	}
	return targets
}

// newFileTarget builds the listing entry for one stored path. The stored path
// is mapped into the process's filesystem space and passed through GuardPath
// exactly like the read/write path, so the listing reports resolved paths,
// explicit existence, and whether the file is currently editable.
func newFileTarget(stack Stack, kind string, index int, stored string, allowedPaths []string) FileTarget {
	resolved := ResolvePathForRuntime(stack, stored)
	target := FileTarget{
		Kind:  kind,
		Index: index,
		Label: filepath.Base(stored),
		Path:  resolved,
	}

	// Report existence and size from the resolved path even when the guard
	// rejects it, so a missing file is distinguishable from an allow-list
	// rejection. Editable stays false until the guard and a regular-file
	// check both pass.
	if info, err := os.Stat(resolved); err == nil {
		target.Exists = true
		target.Size = info.Size()
	}

	guarded, err := GuardPath(resolved, allowedPaths)
	if err != nil {
		return target
	}

	target.Path = guarded
	if info, err := os.Stat(guarded); err == nil {
		target.Exists = true
		target.Size = info.Size()
		target.Editable = info.Mode().IsRegular() && info.Size() <= MaxEditableFileBytes
	}
	return target
}

// ResolveFileTarget maps a client-supplied kind and index onto a real file.
// The client never supplies a path, so traversal is impossible by construction;
// the allow-list and symlink checks still apply as defence in depth.
func ResolveFileTarget(stack Stack, kind string, index int, allowedPaths []string) (FileTarget, error) {
	if index < 0 {
		return FileTarget{}, fmt.Errorf("index must not be negative")
	}

	var chosen string
	switch kind {
	case FileKindCompose:
		if index >= len(stack.ComposeFiles) {
			return FileTarget{}, fmt.Errorf("compose index %d is out of range", index)
		}
		chosen = stack.ComposeFiles[index]
	case FileKindEnv:
		if index >= len(stack.EnvFiles) {
			return FileTarget{}, fmt.Errorf("env index %d is out of range", index)
		}
		chosen = stack.EnvFiles[index]
	default:
		return FileTarget{}, fmt.Errorf("unsupported file kind: %s", kind)
	}

	resolved := ResolvePathForRuntime(stack, chosen)

	guarded, err := GuardPath(resolved, allowedPaths)
	if err != nil {
		// GuardPath resolves symlinks before checking the allow-list, so a
		// target that does not exist fails here rather than at the stat
		// below. Report it as missing so a deleted file is a 404, never the
		// generic 400; any other failure (including an allow-list rejection)
		// keeps its own meaning.
		if errors.Is(err, fs.ErrNotExist) {
			return FileTarget{}, fmt.Errorf("%w: %s", ErrFileMissing, chosen)
		}
		return FileTarget{}, err
	}

	info, err := os.Stat(guarded)
	if err != nil {
		return FileTarget{}, fmt.Errorf("%w: %s", ErrFileMissing, chosen)
	}
	if !info.Mode().IsRegular() {
		return FileTarget{}, fmt.Errorf("%w: %s", ErrFileNotRegular, chosen)
	}
	if info.Size() > MaxEditableFileBytes {
		return FileTarget{}, fmt.Errorf("%w: %s is %d bytes", ErrFileTooLarge, chosen, info.Size())
	}

	return FileTarget{
		Kind:     kind,
		Index:    index,
		Label:    filepath.Base(chosen),
		Path:     guarded,
		Size:     info.Size(),
		Exists:   true,
		Editable: true,
	}, nil
}

// ReadEditableFile reads path through a hard size cap. ResolveFileTarget checks
// the size before reading, but a file can grow or be replaced in between; the
// limit here makes the read itself fail closed instead of pulling a now-huge
// file through the API.
func ReadEditableFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	content, err := io.ReadAll(&io.LimitedReader{R: f, N: MaxEditableFileBytes + 1})
	if err != nil {
		return "", err
	}
	if len(content) > MaxEditableFileBytes {
		return "", fmt.Errorf("%w: %s", ErrFileTooLarge, path)
	}
	return string(content), nil
}

// WriteFileAtomic replaces path's contents without ever exposing a partial
// write, preserving the existing file mode. The temp file is created in the
// same directory, written and synced before the rename so a crash cannot
// publish un-synced or partially written data.
func WriteFileAtomic(path string, content string) error {
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(mode); err != nil {
		return fmt.Errorf("failed to set temporary file mode: %w", err)
	}
	if _, err := tmp.Write([]byte(content)); err != nil {
		return fmt.Errorf("failed to write temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("failed to sync temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("failed to commit file: %w", err)
	}
	committed = true
	return nil
}
