package agent

import (
	"context"
	"os"
	"testing"

	"dockgo/stacks"

	"github.com/docker/docker/api/types/container"
)

func TestHandleEnvelopeNoRequestIDIsNoop(t *testing.T) {
	a := &Agent{}
	ctx := context.Background()
	err := a.handleEnvelope(ctx, nil, Envelope{Type: TypeContainersList})
	if err != nil {
		t.Fatalf("handleEnvelope without request_id should be a no-op, got err: %v", err)
	}
}

func TestHandleEnvelopePongIgnored(t *testing.T) {
	a := &Agent{}
	err := a.handleEnvelope(context.Background(), nil, Envelope{Type: TypePong})
	if err != nil {
		t.Fatalf("pong should be ignored, got err: %v", err)
	}
}

func TestHandleEnvelopeDisconnectErrors(t *testing.T) {
	a := &Agent{}
	err := a.handleEnvelope(context.Background(), nil, Envelope{Type: TypeDisconnect})
	if err == nil {
		t.Fatalf("disconnect should terminate the connect loop")
	}
}

func TestAgentContainerMatchesStackByWorkingDir(t *testing.T) {
	stack := stacks.Stack{
		ProjectName: "registry",
		WorkingDir:  "/compose/registry",
		Discovery: stacks.DiscoverySelector{
			ComposeProject: "registry",
			ServiceNames:   []string{"registry", "registry-ui"},
		},
	}

	c := container.Summary{
		ID: "abc123",
		Labels: map[string]string{
			"com.docker.compose.project":         "registry",
			"com.docker.compose.project.working_dir": "/compose/registry",
			"com.docker.compose.service":         "registry",
		},
	}

	// No managed containers yet: must still match via project + working dir.
	if !agentContainerMatchesStack(stack, c) {
		t.Fatal("container with matching working_dir should match despite empty ManagedContainers")
	}
}

func TestAgentContainerMatchesStackByServiceName(t *testing.T) {
	stack := stacks.Stack{
		ProjectName: "registry",
		WorkingDir:  "/compose/registry",
		Discovery: stacks.DiscoverySelector{
			ComposeProject: "registry",
			ServiceNames:   []string{"registry", "registry-ui"},
		},
	}

	// Container has a different working dir but matches a declared service.
	c := container.Summary{
		ID: "def456",
		Labels: map[string]string{
			"com.docker.compose.project":     "registry",
			"com.docker.compose.service":     "registry-ui",
		},
	}

	if !agentContainerMatchesStack(stack, c) {
		t.Fatal("container matching a declared service should match the stack")
	}
}

func TestAgentContainerMatchesStackByManagedContainer(t *testing.T) {
	stack := stacks.Stack{
		ProjectName:       "registry",
		WorkingDir:        "/compose/registry",
		ManagedContainers: []string{"xyz789"},
		Discovery: stacks.DiscoverySelector{
			ComposeProject: "registry",
		},
	}

	c := container.Summary{
		ID: "xyz789",
		Labels: map[string]string{
			"com.docker.compose.project": "registry",
		},
	}

	if !agentContainerMatchesStack(stack, c) {
		t.Fatal("container explicitly recorded as managed should match")
	}
}

func TestAgentContainerMatchesStackRejectsOtherProject(t *testing.T) {
	stack := stacks.Stack{
		ProjectName: "registry",
		WorkingDir:  "/compose/registry",
		Discovery: stacks.DiscoverySelector{
			ComposeProject: "registry",
		},
	}

	c := container.Summary{
		ID: "other",
		Labels: map[string]string{
			"com.docker.compose.project":         "different-project",
			"com.docker.compose.project.working_dir": "/compose/other",
		},
	}

	if agentContainerMatchesStack(stack, c) {
		t.Fatal("container from a different compose project should not match")
	}
}

func TestAgentContainerMatchesStackWindowsPathMapping(t *testing.T) {
	stack := stacks.Stack{
		ProjectName: "bazarr",
		WorkingDir:  "D:\\Docker\\bazarr",
		PathMode:    stacks.PathModeMapped,
		PathMappings: []stacks.PathMapping{
			{HostPath: "D:\\Docker", ContainerPath: "/compose"},
		},
		Discovery: stacks.DiscoverySelector{
			ComposeProject: "bazarr",
			ServiceNames:   []string{"bazarr"},
		},
	}

	// The container's label carries the mapped runtime path.
	c := container.Summary{
		ID: "baz",
		Labels: map[string]string{
			"com.docker.compose.project":         "bazarr",
			"com.docker.compose.project.working_dir": "/compose/bazarr",
			"com.docker.compose.service":         "bazarr",
		},
	}

	if !agentContainerMatchesStack(stack, c) {
		t.Fatal("container with mapped runtime working_dir should match via ResolvePathForRuntime")
	}
}

func TestAgentSuggestComposeFilesTrustsConfigFilesLabel(t *testing.T) {
	tempDir := t.TempDir()
	labelFile := tempDir + "/docker-compose-agent.yml"
	if err := os.WriteFile(labelFile, []byte("services: {}"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(tempDir+"/compose.yml", []byte("services: {}"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// All label paths are trusted as-is and deduped; the missing.yml entry is
	// kept because the label is authoritative even when not mounted locally.
	got := agentSuggestComposeFiles(tempDir, []string{labelFile, tempDir + "/missing.yml", labelFile})

	if len(got) != 2 || got[0] != labelFile || got[1] != tempDir+"/missing.yml" {
		t.Fatalf("agentSuggestComposeFiles() = %v, want [%q %q] (label paths trusted, deduped)", got, labelFile, tempDir+"/missing.yml")
	}
}

func TestAgentSuggestComposeFilesTrustsLabelNotMountedInAgentContainer(t *testing.T) {
	// The config_files label is written by Compose on the daemon host and is
	// authoritative even when the path is not mounted inside the agent container
	// (which only mounts COMPOSE_PATH_MAPPING paths). It must not be discarded
	// just because os.Stat fails here.
	hostOnlyFile := `/root/docker/gotify/compose.yaml`

	got := agentSuggestComposeFiles("/root/docker/gotify", []string{hostOnlyFile})

	if len(got) != 1 || got[0] != hostOnlyFile {
		t.Fatalf("agentSuggestComposeFiles() = %v, want [%q] (label trusted without existence check)", got, hostOnlyFile)
	}
}

func TestAgentSuggestComposeFilesFallsBackToProbing(t *testing.T) {
	tempDir := t.TempDir()
	composePath := agentJoinPath(tempDir, "compose.yaml")
	if err := os.WriteFile(composePath, []byte("services: {}"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	got := agentSuggestComposeFiles(tempDir, nil)

	if len(got) != 1 || got[0] != composePath {
		t.Fatalf("agentSuggestComposeFiles() = %v, want [%q] via probing fallback", got, composePath)
	}
}

func TestAgentSuggestComposeFilesReturnsEmptyWhenNothingExists(t *testing.T) {
	tempDir := t.TempDir()

	got := agentSuggestComposeFiles(tempDir, nil)

	if len(got) != 0 {
		t.Fatalf("agentSuggestComposeFiles() = %v, want empty slice", got)
	}
}

func TestAgentSuggestComposeFileNeverFabricatesPath(t *testing.T) {
	tempDir := t.TempDir()

	if got := agentSuggestComposeFile(tempDir); got != "" {
		t.Fatalf("agentSuggestComposeFile() = %q, want empty string for missing files", got)
	}
}
