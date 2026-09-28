package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"dockgo/stacks"
)

// maxEditableFileBytes caps editor reads and writes so a huge or unexpected
// file cannot be pulled through the API.
const maxEditableFileBytes = 1 << 20

// Sentinel errors let handlers map a failed target resolution onto the status
// codes in the design (403 outside the allow-list or not a regular file, 413 too
// large, 404 missing) instead of collapsing every failure into 400.
var (
	errFileMissing    = errors.New("file does not exist")
	errFileTooLarge   = errors.New("file exceeds the editable size limit")
	errFileNotRegular = errors.New("file is not a regular file")
)

// fileTarget is one editable file of a stack, addressed by kind and index.
type fileTarget struct {
	Kind  string `json:"kind"`
	Index int    `json:"index"`
	Label string `json:"label"`
	Path  string `json:"path"`
	Size  int64  `json:"size"`
}

// fileTargets lists the editable files of a stack: compose files first, then
// env files. The order defines the index space the client uses.
func fileTargets(stack stacks.Stack) []fileTarget {
	targets := make([]fileTarget, 0, len(stack.ComposeFiles)+len(stack.EnvFiles))

	for i, path := range stack.ComposeFiles {
		targets = append(targets, newFileTarget(stacks.FileKindCompose, i, path))
	}
	for i, path := range stack.EnvFiles {
		targets = append(targets, newFileTarget(stacks.FileKindEnv, i, path))
	}
	return targets
}

func newFileTarget(kind string, index int, path string) fileTarget {
	target := fileTarget{
		Kind:  kind,
		Index: index,
		Label: filepath.Base(path),
		Path:  path,
	}
	if info, err := os.Stat(path); err == nil {
		target.Size = info.Size()
	}
	return target
}

// resolveFileTarget maps a client-supplied kind and index onto a real file.
// The client never supplies a path, so traversal is impossible by construction;
// the allow-list and symlink checks still apply as defence in depth.
func (s *Server) resolveFileTarget(stack stacks.Stack, kind string, index int) (fileTarget, error) {
	if index < 0 {
		return fileTarget{}, fmt.Errorf("index must not be negative")
	}

	var chosen string
	switch kind {
	case stacks.FileKindCompose:
		if index >= len(stack.ComposeFiles) {
			return fileTarget{}, fmt.Errorf("compose index %d is out of range", index)
		}
		chosen = stack.ComposeFiles[index]
	case stacks.FileKindEnv:
		if index >= len(stack.EnvFiles) {
			return fileTarget{}, fmt.Errorf("env index %d is out of range", index)
		}
		chosen = stack.EnvFiles[index]
	default:
		return fileTarget{}, fmt.Errorf("unsupported file kind: %s", kind)
	}

	resolved := stacks.ResolvePathForRuntime(stack, chosen)

	guarded, err := stacks.GuardPath(resolved, s.AllowedPaths)
	if err != nil {
		// GuardPath resolves symlinks before checking the allow-list, so a
		// target that does not exist fails here rather than at the stat
		// below. Report it as missing so a deleted file is a 404, never the
		// generic 400; any other failure (including an allow-list rejection)
		// keeps its own meaning.
		if errors.Is(err, fs.ErrNotExist) {
			return fileTarget{}, fmt.Errorf("%w: %s", errFileMissing, chosen)
		}
		return fileTarget{}, err
	}

	info, err := os.Stat(guarded)
	if err != nil {
		return fileTarget{}, fmt.Errorf("%w: %s", errFileMissing, chosen)
	}
	if !info.Mode().IsRegular() {
		return fileTarget{}, fmt.Errorf("%w: %s", errFileNotRegular, chosen)
	}
	if info.Size() > maxEditableFileBytes {
		return fileTarget{}, fmt.Errorf("%w: %s is %d bytes", errFileTooLarge, chosen, info.Size())
	}

	return fileTarget{Kind: kind, Index: index, Label: filepath.Base(chosen), Path: guarded, Size: info.Size()}, nil
}

// fileTargetStatus maps a target-resolution failure onto an HTTP status.
func fileTargetStatus(err error) int {
	switch {
	case errors.Is(err, stacks.ErrPathNotAllowed), errors.Is(err, errFileNotRegular):
		return http.StatusForbidden
	case errors.Is(err, errFileTooLarge):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, errFileMissing):
		return http.StatusNotFound
	default:
		return http.StatusBadRequest
	}
}

func fileTargetRequest(r *http.Request) (string, int, error) {
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	if kind == "" {
		return "", 0, fmt.Errorf("kind is required")
	}

	rawIndex := strings.TrimSpace(r.URL.Query().Get("index"))
	if rawIndex == "" {
		return "", 0, fmt.Errorf("index is required")
	}
	index, err := strconv.Atoi(rawIndex)
	if err != nil {
		return "", 0, fmt.Errorf("index must be an integer")
	}
	return kind, index, nil
}

func (s *Server) handleStackFiles(w http.ResponseWriter, stack stacks.Stack) {
	writeJSON(w, http.StatusOK, map[string]any{"files": fileTargets(stack)})
}

func (s *Server) handleStackFileRead(w http.ResponseWriter, stack stacks.Stack, r *http.Request) {
	kind, index, err := fileTargetRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	target, err := s.resolveFileTarget(stack, kind, index)
	if err != nil {
		writeError(w, fileTargetStatus(err), err.Error())
		return
	}

	content, err := os.ReadFile(target.Path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"target":  target,
		"content": string(content),
	})
}

// handleStackFileValidate checks draft content without writing anything, so the
// editor can validate while typing.
func (s *Server) handleStackFileValidate(w http.ResponseWriter, stack stacks.Stack, r *http.Request) {
	kind, index, err := fileTargetRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.resolveFileTarget(stack, kind, index); err != nil {
		writeError(w, fileTargetStatus(err), err.Error())
		return
	}

	var payload struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	writeJSON(w, http.StatusOK, stacks.ValidateSyntax(kind, payload.Content))
}
