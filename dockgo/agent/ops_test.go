package agent

import (
	"context"
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
