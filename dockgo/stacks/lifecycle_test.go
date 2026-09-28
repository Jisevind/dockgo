package stacks

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeFakeDocker installs a stub `docker` on PATH that records its arguments
// to a log file and emits plausible `compose config` JSON so Validate passes.
func writeFakeDocker(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stub docker relies on a POSIX shell script")
	}

	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$*\" >> \"" + logPath + "\"\n" +
		"case \"$*\" in\n" +
		"  *\"compose\"*\"config\"*)\n" +
		"    printf '%s' '{\"services\":{\"web\":{\"image\":\"nginx\"}}}'\n" +
		"    ;;\n" +
		"esac\n" +
		"exit 0\n"

	binPath := filepath.Join(dir, "docker")
	if err := os.WriteFile(binPath, []byte(script), 0o700); err != nil {
		t.Fatalf("WriteFile(docker stub) error = %v", err)
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

func newRunnableStack(t *testing.T) Stack {
	t.Helper()
	dir := t.TempDir()
	composeFile := filepath.Join(dir, "compose.yaml")
	if err := os.WriteFile(composeFile, []byte("services:\n  web:\n    image: nginx\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(compose) error = %v", err)
	}
	return Stack{
		Name:         "demo",
		ProjectName:  "demo",
		WorkingDir:   dir,
		ComposeFiles: []string{composeFile},
		PathMode:     PathModeHostNative,
	}
}

// TestStartStopInvokeComposeSubcommands pins the compose verbs the dashboard's
// stack menu depends on. Start must map to `compose start`; Stop must map to
// `compose stop` (which leaves containers in place, unlike `down`).
func TestStartStopInvokeComposeSubcommands(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(context.Context, Stack, Logger) error
		want string
	}{
		{name: "start", run: Start, want: "compose -p demo -f"},
		{name: "stop", run: Stop, want: "compose -p demo -f"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logPath := writeFakeDocker(t)
			stack := newRunnableStack(t)

			var lines []string
			if err := tc.run(context.Background(), stack, func(s string) {
				lines = append(lines, s)
			}); err != nil {
				t.Fatalf("%s() error = %v", tc.name, err)
			}

			recorded, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatalf("ReadFile(calls) error = %v", err)
			}
			calls := string(recorded)

			// The lifecycle verb must appear as its own argv element.
			if !strings.Contains(calls, " "+tc.name) {
				t.Fatalf("docker calls = %q, want a %q subcommand", calls, tc.name)
			}
			// `stop` must never escalate to `down`, which removes containers.
			if tc.name == "stop" && strings.Contains(calls, " down") {
				t.Fatalf("docker calls = %q, stop must not run compose down", calls)
			}
			if !strings.Contains(calls, tc.want) {
				t.Fatalf("docker calls = %q, want it to include %q", calls, tc.want)
			}
		})
	}
}

// TestStopDoesNotRunDown guards the semantic difference between the two
// dashboard actions: stop halts containers, down removes them.
func TestStopDoesNotRunDown(t *testing.T) {
	logPath := writeFakeDocker(t)
	stack := newRunnableStack(t)

	if err := Stop(context.Background(), stack, nil); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	recorded, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile(calls) error = %v", err)
	}
	if strings.Contains(string(recorded), " down") {
		t.Fatalf("Stop() ran compose down: %s", recorded)
	}
}

// TestDownRunsComposeDown confirms down keeps its removing semantics.
func TestDownRunsComposeDown(t *testing.T) {
	logPath := writeFakeDocker(t)
	stack := newRunnableStack(t)

	if err := Down(context.Background(), stack, nil); err != nil {
		t.Fatalf("Down() error = %v", err)
	}

	recorded, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile(calls) error = %v", err)
	}
	if !strings.Contains(string(recorded), " down") {
		t.Fatalf("Down() did not run compose down: %s", recorded)
	}
}

// TestStartFailsOnValidationError ensures a bad stack is rejected before any
// compose command is invoked.
func TestStartFailsOnValidationError(t *testing.T) {
	logPath := writeFakeDocker(t)

	err := Start(context.Background(), Stack{Name: "broken"}, nil)
	if err == nil {
		t.Fatal("Start() = nil error, want validation failure")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Fatalf("Start() error = %q, want validation failure", err)
	}

	if recorded, readErr := os.ReadFile(logPath); readErr == nil && len(recorded) > 0 {
		t.Fatalf("docker was invoked despite invalid stack: %s", recorded)
	}
}
