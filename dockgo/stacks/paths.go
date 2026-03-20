package stacks

import (
	"os"
	"path/filepath"
	"strings"
)

func isWindowsAbs(path string) bool {
	if len(path) < 3 {
		return false
	}
	drive := path[0]
	return ((drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z')) &&
		path[1] == ':' &&
		(path[2] == '\\' || path[2] == '/')
}

func isAbsPath(path string) bool {
	return filepath.IsAbs(path) || isWindowsAbs(path)
}

func defaultMappings() []PathMapping {
	raw := strings.TrimSpace(os.Getenv("COMPOSE_PATH_MAPPING"))
	if raw == "" {
		return nil
	}

	entries := strings.Split(raw, ",")
	mappings := make([]PathMapping, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		lastColon := strings.LastIndex(entry, ":")
		if lastColon <= 0 {
			continue
		}

		hostPath := strings.TrimSpace(entry[:lastColon])
		containerPath := strings.TrimSpace(entry[lastColon+1:])
		if hostPath == "" || containerPath == "" {
			continue
		}

		mappings = append(mappings, PathMapping{
			HostPath:      hostPath,
			ContainerPath: containerPath,
		})
	}

	return mappings
}

func effectiveMappings(stack Stack) []PathMapping {
	if len(stack.PathMappings) > 0 {
		return stack.PathMappings
	}
	return defaultMappings()
}

func translatePath(path string, mappings []PathMapping) string {
	if path == "" {
		return path
	}

	normalizedPath := strings.ReplaceAll(path, "\\", "/")
	for _, mapping := range mappings {
		hostPath := strings.ReplaceAll(strings.TrimSpace(mapping.HostPath), "\\", "/")
		containerPath := strings.TrimSpace(mapping.ContainerPath)
		if hostPath == "" || containerPath == "" {
			continue
		}

		if strings.HasPrefix(strings.ToLower(normalizedPath), strings.ToLower(hostPath)) {
			remainder := normalizedPath[len(hostPath):]
			return filepath.Clean(containerPath + remainder)
		}
	}

	return path
}

func reverseTranslatePath(path string, mappings []PathMapping) string {
	if path == "" {
		return path
	}

	normalizedPath := strings.ReplaceAll(path, "\\", "/")
	for _, mapping := range mappings {
		hostPath := strings.TrimSpace(mapping.HostPath)
		containerPath := strings.ReplaceAll(strings.TrimSpace(mapping.ContainerPath), "\\", "/")
		if hostPath == "" || containerPath == "" {
			continue
		}

		if strings.HasPrefix(strings.ToLower(normalizedPath), strings.ToLower(containerPath)) {
			remainder := normalizedPath[len(containerPath):]
			if isWindowsAbs(hostPath) || strings.Contains(hostPath, "\\") {
				remainder = strings.ReplaceAll(remainder, "/", "\\")
				hostPath = strings.ReplaceAll(hostPath, "/", "\\")
				return strings.TrimRight(hostPath, "\\/") + remainder
			}
			return filepath.Clean(hostPath + remainder)
		}
	}

	return path
}

func resolvePathForRuntime(stack Stack, path string) string {
	if stack.PathMode != PathModeMapped {
		return path
	}
	return translatePath(path, effectiveMappings(stack))
}

func normalizePathForStorage(stack Stack, path string) string {
	if stack.PathMode != PathModeMapped {
		return path
	}
	return reverseTranslatePath(path, effectiveMappings(stack))
}

func normalizeStackForStorage(stack Stack) Stack {
	stack.WorkingDir = normalizePathForStorage(stack, stack.WorkingDir)
	for i, composeFile := range stack.ComposeFiles {
		stack.ComposeFiles[i] = normalizePathForStorage(stack, composeFile)
	}
	for i, envFile := range stack.EnvFiles {
		stack.EnvFiles[i] = normalizePathForStorage(stack, envFile)
	}
	return stack
}

func ResolvePathForRuntime(stack Stack, path string) string {
	return resolvePathForRuntime(stack, path)
}
