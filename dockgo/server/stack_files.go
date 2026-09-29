package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"dockgo/engine"
	"dockgo/stacks"
)

// errBodyTooLarge marks a request body that exceeds the editable size limit.
var errBodyTooLarge = errors.New("request body exceeds the editable size limit")

// Target resolution, the limited read and the atomic write live in
// dockgo/stacks so the server and the agent share one implementation; the
// server passes s.AllowedPaths as the allow-list.

// fileTargetStatus maps a target-resolution failure onto an HTTP status.
func fileTargetStatus(err error) int {
	switch {
	case errors.Is(err, stacks.ErrPathNotAllowed), errors.Is(err, stacks.ErrFileNotRegular):
		return http.StatusForbidden
	case errors.Is(err, stacks.ErrFileTooLarge):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, stacks.ErrFileMissing):
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
	writeJSON(w, http.StatusOK, map[string]any{"files": stacks.FileTargets(stack, s.AllowedPaths)})
}

func (s *Server) handleStackFileRead(w http.ResponseWriter, stack stacks.Stack, r *http.Request) {
	kind, index, err := fileTargetRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	target, err := stacks.ResolveFileTarget(stack, kind, index, s.AllowedPaths)
	if err != nil {
		writeError(w, fileTargetStatus(err), err.Error())
		return
	}

	content, err := stacks.ReadEditableFile(target.Path)
	if err != nil {
		if errors.Is(err, stacks.ErrFileTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"target":  target,
		"content": content,
	})
}

// fileContentPayload is the JSON body shared by the validate and save
// endpoints.
type fileContentPayload struct {
	Content string `json:"content"`
}

// decodeFileContentPayload decodes a file-editor request body behind a hard
// size cap so an oversized body is refused before it can be fully allocated.
// errBodyTooLarge is returned when the cap is exceeded.
func decodeFileContentPayload(w http.ResponseWriter, r *http.Request, payload *fileContentPayload) error {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, stacks.MaxEditableFileBytes+4096)).Decode(payload); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return fmt.Errorf("%w: request body exceeds the %d byte limit", errBodyTooLarge, stacks.MaxEditableFileBytes)
		}
		return err
	}
	return nil
}

// handleStackFileValidate checks draft content without writing anything, so the
// editor can validate while typing.
func (s *Server) handleStackFileValidate(w http.ResponseWriter, stack stacks.Stack, r *http.Request) {
	kind, index, err := fileTargetRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := stacks.ResolveFileTarget(stack, kind, index, s.AllowedPaths); err != nil {
		writeError(w, fileTargetStatus(err), err.Error())
		return
	}

	var payload fileContentPayload
	if err := decodeFileContentPayload(w, r, &payload); err != nil {
		if errors.Is(err, errBodyTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	writeJSON(w, http.StatusOK, stacks.ValidateSyntax(kind, payload.Content))
}

// handleStackFileWrite saves new content for one stack file.
//
// Order is deliberate: syntax is checked before anything touches the disk, the
// project lock is taken before the previous content is read so a save cannot
// interleave with a deploy, and the previous content is restored if docker
// rejects the result. A save that does not pass semantic validation must never
// persist.
func (s *Server) handleStackFileWrite(w http.ResponseWriter, stack stacks.Stack, r *http.Request) {
	kind, index, err := fileTargetRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	target, err := stacks.ResolveFileTarget(stack, kind, index, s.AllowedPaths)
	if err != nil {
		writeError(w, fileTargetStatus(err), err.Error())
		return
	}

	var payload fileContentPayload
	if err := decodeFileContentPayload(w, r, &payload); err != nil {
		if errors.Is(err, errBodyTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(payload.Content) > stacks.MaxEditableFileBytes {
		writeError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("content exceeds the %d byte limit", stacks.MaxEditableFileBytes))
		return
	}

	if syntax := stacks.ValidateSyntax(kind, payload.Content); !syntax.Valid {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error":  "file has syntax errors",
			"syntax": syntax,
		})
		return
	}

	project := stack.Discovery.ComposeProject
	if project == "" {
		project = stack.ProjectName
	}

	var unlock func()
	if project != "" {
		unlock = engine.LockProject(project)
	} else {
		unlock = engine.LockProject(stack.ID)
	}
	defer unlock()

	previous, err := os.ReadFile(target.Path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := stacks.WriteFileAtomic(target.Path, payload.Content); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Validate reads the file from disk, so this checks what was just written.
	// Bound it so a hung compose subprocess cannot hold the project lock
	// indefinitely.
	validationCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	validation := stacks.Validate(validationCtx, stack)
	cancel()
	if !validation.Valid {
		if restoreErr := stacks.WriteFileAtomic(target.Path, string(previous)); restoreErr != nil {
			writeError(w, http.StatusInternalServerError,
				fmt.Sprintf("validation failed and rollback failed: %v", restoreErr))
			return
		}
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error":       "file failed compose validation",
			"validation":  validation,
			"rolled_back": true,
		})
		return
	}

	action := "edit compose"
	if kind == stacks.FileKindEnv {
		action = "edit env"
	}
	delta := len(payload.Content) - len(previous)
	s.recordStackHistory(stack, action, "success",
		fmt.Sprintf("%s updated (%s, %+d bytes)", target.Label, kind, delta))

	writeJSON(w, http.StatusOK, map[string]any{"target": target})
}
