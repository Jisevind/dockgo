package stacks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CreateEnvFile creates a new empty env file for a stack and returns the stored
// host-style path. The file name must be a plain file name; path separators are
// rejected so the file always lands directly in the stack's working directory.
func CreateEnvFile(stack Stack, name string, allowedPaths []string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." ||
		strings.ContainsAny(name, `/\`) {
		return "", errors.New("env file name must be a file name without path separators")
	}
	if strings.TrimSpace(stack.WorkingDir) == "" {
		return "", errors.New("stack working directory is required")
	}

	storedPath := filepath.Join(stack.WorkingDir, name)
	runtimePath := ResolvePathForRuntime(stack, storedPath)

	parent, err := GuardPath(filepath.Dir(runtimePath), allowedPaths)
	if err != nil {
		return "", err
	}
	target := filepath.Join(parent, name)

	if _, err := os.Stat(target); err == nil {
		return "", fmt.Errorf("env file already exists: %s", storedPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	return storedPath, nil
}
