package stacks

import (
	"strings"
	"testing"
)

func TestResolvePathForRuntimeMappedWindowsPath(t *testing.T) {
	stack := Stack{
		PathMode: PathModeMapped,
		PathMappings: []PathMapping{
			{HostPath: `D:\Docker`, ContainerPath: "/compose"},
		},
	}

	got := ResolvePathForRuntime(stack, `D:\Docker\bazarr\compose.yaml`)
	want := `/compose/bazarr/compose.yaml`
	if strings.ReplaceAll(got, `\`, `/`) != want {
		t.Fatalf("ResolvePathForRuntime() = %q, want %q", got, want)
	}
}

func TestResolvePathForRuntimeMappedWithoutMatchKeepsOriginal(t *testing.T) {
	stack := Stack{
		PathMode: PathModeMapped,
		PathMappings: []PathMapping{
			{HostPath: `D:\Docker`, ContainerPath: "/compose"},
		},
	}

	original := `E:\Other\bazarr\compose.yaml`
	got := ResolvePathForRuntime(stack, original)
	if got != original {
		t.Fatalf("ResolvePathForRuntime() = %q, want unchanged %q", got, original)
	}
}

func TestNormalizeStackForStorageReverseTranslatesMappedPaths(t *testing.T) {
	stack := Stack{
		PathMode:   PathModeMapped,
		WorkingDir: `/compose/bazarr`,
		ComposeFiles: []string{
			`/compose/bazarr/compose.yaml`,
		},
		EnvFiles: []string{
			`/compose/bazarr/.env`,
		},
		PathMappings: []PathMapping{
			{HostPath: `D:\Docker`, ContainerPath: "/compose"},
		},
	}

	got := normalizeStackForStorage(stack)

	if got.WorkingDir != `D:\Docker\bazarr` {
		t.Fatalf("WorkingDir = %q, want %q", got.WorkingDir, `D:\Docker\bazarr`)
	}
	if got.ComposeFiles[0] != `D:\Docker\bazarr\compose.yaml` {
		t.Fatalf("ComposeFiles[0] = %q, want %q", got.ComposeFiles[0], `D:\Docker\bazarr\compose.yaml`)
	}
	if got.EnvFiles[0] != `D:\Docker\bazarr\.env` {
		t.Fatalf("EnvFiles[0] = %q, want %q", got.EnvFiles[0], `D:\Docker\bazarr\.env`)
	}
}
