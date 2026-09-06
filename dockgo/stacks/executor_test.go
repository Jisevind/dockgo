package stacks

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestHelperProcess is a fake command that writes diagnostic output to stderr
// and exits non-zero, simulating a failing docker command. It is invoked by
// StreamCommand tests via the child-process pattern.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("DOCKGO_HELPER_PROCESS") != "1" {
		return
	}
	_, _ = os.Stderr.WriteString("Error response from daemon: failed to resolve reference \"example.com/app:v1\": not found\n")
	os.Exit(1)
}

func TestStreamCommandErrorIncludesStderr(t *testing.T) {
	// The child process inherits the parent environment; the helper only acts
	// when this var is set.
	if err := os.Setenv("DOCKGO_HELPER_PROCESS", "1"); err != nil {
		t.Fatalf("Setenv() error = %v", err)
	}
	defer func() { _ = os.Unsetenv("DOCKGO_HELPER_PROCESS") }()

	var lines []string
	err := StreamCommand(context.Background(), t.TempDir(),
		func(s string) { lines = append(lines, s) },
		os.Args[0], "-test.run=TestHelperProcess",
	)
	if err == nil {
		t.Fatal("streamCommand() = nil error, want non-nil for failing command")
	}

	// The returned error must surface the underlying diagnostic so the UI and
	// history show why the operation failed instead of a bare "exit status 1".
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("streamCommand() error = %q, want it to include stderr diagnostic", err)
	}

	// The streamed lines must include the stderr output too.
	found := false
	for _, l := range lines {
		if strings.Contains(l, "not found") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("streamed lines = %q, want them to include stderr output", lines)
	}
}

func TestStreamCommandSuccess(t *testing.T) {
	if err := os.Setenv("DOCKGO_HELPER_PROCESS", "1"); err != nil {
		t.Fatalf("Setenv() error = %v", err)
	}
	defer func() { _ = os.Unsetenv("DOCKGO_HELPER_PROCESS") }()

	var lines []string
	err := StreamCommand(context.Background(), t.TempDir(),
		func(s string) { lines = append(lines, s) },
		os.Args[0], "-test.run=TestHelperProcessSuccess",
	)
	if err != nil {
		t.Fatalf("streamCommand() error = %v, want nil for successful command", err)
	}
	if len(lines) == 0 {
		t.Fatal("streamCommand() streamed no lines, want stdout output")
	}
}

func TestHelperProcessSuccess(t *testing.T) {
	if os.Getenv("DOCKGO_HELPER_PROCESS") != "1" {
		return
	}
	_, _ = os.Stdout.WriteString("Pulling image...\n")
	os.Exit(0)
}
