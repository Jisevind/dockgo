package stacks

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// ErrPathNotAllowed is returned when a path resolves outside the configured
// ALLOWED_COMPOSE_PATHS allow-list.
var ErrPathNotAllowed = errors.New("path is not within the allowed compose paths")

// resolveAllowListBase maps a configured allow-list entry into the filesystem
// space this process actually uses.
//
// ALLOWED_COMPOSE_PATHS is documented in host terms (for example
// /home/user/docker) while the server may see the same tree under a mapped
// prefix (for example /compose). Comparing the two forms directly is what made
// the allow-list reject valid compose directories. Entries that cannot be
// resolved are skipped rather than fatal, so one stale entry does not disable
// the others.
func resolveAllowListBase(base string) (string, bool) {
	translated := translatePath(base, defaultMappings())
	if strings.TrimSpace(translated) == "" {
		return "", false
	}

	realBase, err := filepath.EvalSymlinks(filepath.Clean(translated))
	if err != nil {
		return "", false
	}
	return realBase, true
}

// GuardPath resolves path and verifies it sits inside one of allowedPaths.
//
// The candidate is expected to be in this process's filesystem space (callers
// pass ResolvePathForRuntime output). Every allow-list entry is translated
// through COMPOSE_PATH_MAPPING first, so a host-style configuration works
// whether this process sees host paths or mapped container paths. An empty
// allow-list disables the check, matching the documented behaviour.
//
// The resolved real path is returned so callers perform filesystem access on
// exactly the path that was checked.
func GuardPath(path string, allowedPaths []string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("path is required")
	}

	realPath, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("failed to resolve path: %w", err)
	}
	if !filepath.IsAbs(realPath) {
		return "", fmt.Errorf("path must be absolute: %s", realPath)
	}

	if len(allowedPaths) == 0 {
		return realPath, nil
	}

	for _, base := range allowedPaths {
		realBase, ok := resolveAllowListBase(base)
		if !ok {
			continue
		}
		base := realBase
		if !strings.HasSuffix(base, string(filepath.Separator)) {
			base += string(filepath.Separator)
		}
		if realPath == realBase || strings.HasPrefix(realPath, base) {
			return realPath, nil
		}
	}

	return "", fmt.Errorf("%w: %s (allowed: %v)", ErrPathNotAllowed, realPath, allowedPaths)
}
