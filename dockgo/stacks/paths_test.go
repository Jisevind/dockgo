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

func TestTranslatePathForRuntimeAppliesDefaultMappings(t *testing.T) {
	t.Setenv("COMPOSE_PATH_MAPPING", "/root/docker:/compose")

	got := TranslatePathForRuntime(`/root/docker/umami/compose.yaml`)
	want := `/compose/umami/compose.yaml`
	if strings.ReplaceAll(got, `\`, `/`) != want {
		t.Fatalf("TranslatePathForRuntime() = %q, want %q", got, want)
	}
}

func TestTranslatePathForRuntimeKeepsUnmatchedPath(t *testing.T) {
	t.Setenv("COMPOSE_PATH_MAPPING", "/root/docker:/compose")

	got := TranslatePathForRuntime(`/srv/apps/umami/compose.yaml`)
	if got != `/srv/apps/umami/compose.yaml` {
		t.Fatalf("TranslatePathForRuntime() = %q, want unchanged", got)
	}
}

func TestTranslatePathForRuntimeNoMappingEnv(t *testing.T) {
	t.Setenv("COMPOSE_PATH_MAPPING", "")

	got := TranslatePathForRuntime(`/root/docker/umami/compose.yaml`)
	if got != `/root/docker/umami/compose.yaml` {
		t.Fatalf("TranslatePathForRuntime() = %q, want unchanged when no mappings configured", got)
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

func TestTranslatePathRejectsSiblingDirectory(t *testing.T) {
	mappings := []PathMapping{{HostPath: "/app", ContainerPath: "/compose"}}

	// "/app-secret/file.txt" must NOT match the "/app" mapping
	got := translatePath("/app-secret/file.txt", mappings)
	if got != "/app-secret/file.txt" {
		t.Fatalf("translatePath() = %q, want unchanged (sibling dir must not match)", got)
	}

	// "/app/file.txt" SHOULD match
	got = translatePath("/app/file.txt", mappings)
	want := "/compose/file.txt"
	if strings.ReplaceAll(got, `\`, `/`) != want {
		t.Fatalf("translatePath() = %q, want %q", got, want)
	}

	// Exact match (no remainder) should work
	got = translatePath("/app", mappings)
	want = "/compose"
	if strings.ReplaceAll(got, `\`, `/`) != want {
		t.Fatalf("translatePath() = %q, want %q", got, want)
	}
}

func TestReverseTranslatePathRejectsSiblingDirectory(t *testing.T) {
	mappings := []PathMapping{{HostPath: "/host/data", ContainerPath: "/compose"}}

	got := reverseTranslatePath("/compose-other/file.txt", mappings)
	if got != "/compose-other/file.txt" {
		t.Fatalf("reverseTranslatePath() = %q, want unchanged", got)
	}

	got = reverseTranslatePath("/compose/file.txt", mappings)
	want := "/host/data/file.txt"
	if strings.ReplaceAll(got, `\`, `/`) != want {
		t.Fatalf("reverseTranslatePath() = %q, want %q", got, want)
	}
}
