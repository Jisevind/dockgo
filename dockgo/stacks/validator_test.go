package stacks

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

func TestValidateRejectsUnresolvedMappedWindowsWorkingDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test targets non-Windows DockGo runtime behavior")
	}

	stack := Stack{
		Name:         "bazarr",
		ProjectName:  "bazarr",
		WorkingDir:   `D:\Docker\bazarr`,
		ComposeFiles: []string{`D:\Docker\bazarr\compose.yaml`},
		PathMode:     PathModeMapped,
	}

	result := Validate(context.Background(), stack)

	if result.Valid {
		t.Fatalf("Validate() valid = true, want false")
	}
	if !containsIssueText(result.Issues, "working_dir cannot be resolved inside DockGo from Windows host path") {
		t.Fatalf("expected working_dir resolution issue, got %+v", result.Issues)
	}
	if !containsIssueText(result.Issues, "compose file cannot be resolved inside DockGo from Windows host path") {
		t.Fatalf("expected compose file resolution issue, got %+v", result.Issues)
	}
}

func TestValidateRejectsUnresolvedMappedWindowsEnvFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test targets non-Windows DockGo runtime behavior")
	}

	stack := Stack{
		Name:         "bazarr",
		ProjectName:  "bazarr",
		WorkingDir:   `D:\Docker\bazarr`,
		ComposeFiles: []string{`D:\Docker\bazarr\compose.yaml`},
		EnvFiles:     []string{`D:\Docker\bazarr\.env`},
		PathMode:     PathModeMapped,
		PathMappings: []PathMapping{
			{HostPath: `D:\Other`, ContainerPath: "/compose"},
		},
	}

	result := Validate(context.Background(), stack)

	if result.Valid {
		t.Fatalf("Validate() valid = true, want false")
	}
	if !containsIssueText(result.Issues, "env file cannot be resolved inside DockGo from Windows host path") {
		t.Fatalf("expected env file resolution issue, got %+v", result.Issues)
	}
}

func containsIssueText(issues []string, needle string) bool {
	for _, issue := range issues {
		if strings.Contains(issue, needle) {
			return true
		}
	}
	return false
}
