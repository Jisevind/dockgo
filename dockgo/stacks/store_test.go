package stacks

import (
	"path/filepath"
	"testing"
)

func TestFindForComposeTargetSingleProjectMatch(t *testing.T) {
	store := &Store{
		path: filepath.Join(t.TempDir(), "stacks.json"),
		stacks: map[string]Stack{
			"1": {
				ID:          "1",
				Name:        "bazarr",
				ProjectName: "bazarr",
			},
		},
	}

	got, ok := store.FindForComposeTarget("bazarr", "", "")
	if !ok {
		t.Fatal("FindForComposeTarget() did not match expected stack")
	}
	if got.ID != "1" {
		t.Fatalf("matched stack ID = %q, want %q", got.ID, "1")
	}
}

func TestFindForComposeTargetUsesWorkingDirToBreakTies(t *testing.T) {
	store := &Store{
		path: filepath.Join(t.TempDir(), "stacks.json"),
		stacks: map[string]Stack{
			"1": {
				ID:          "1",
				Name:        "bazarr-a",
				ProjectName: "bazarr",
				WorkingDir:  `/srv/apps/a`,
			},
			"2": {
				ID:          "2",
				Name:        "bazarr-b",
				ProjectName: "bazarr",
				WorkingDir:  `/srv/apps/b`,
			},
		},
	}

	got, ok := store.FindForComposeTarget("bazarr", `/srv/apps/b`, "")
	if !ok {
		t.Fatal("FindForComposeTarget() did not match expected stack")
	}
	if got.ID != "2" {
		t.Fatalf("matched stack ID = %q, want %q", got.ID, "2")
	}
}

func TestFindForComposeTargetUsesServiceNamesToBreakTies(t *testing.T) {
	store := &Store{
		path: filepath.Join(t.TempDir(), "stacks.json"),
		stacks: map[string]Stack{
			"1": {
				ID:          "1",
				Name:        "media-a",
				ProjectName: "media",
				Discovery: DiscoverySelector{
					ServiceNames: []string{"radarr"},
				},
			},
			"2": {
				ID:          "2",
				Name:        "media-b",
				ProjectName: "media",
				Discovery: DiscoverySelector{
					ServiceNames: []string{"sonarr"},
				},
			},
		},
	}

	got, ok := store.FindForComposeTarget("media", "", "sonarr")
	if !ok {
		t.Fatal("FindForComposeTarget() did not match expected stack")
	}
	if got.ID != "2" {
		t.Fatalf("matched stack ID = %q, want %q", got.ID, "2")
	}
}

func TestFindForComposeTargetFailsClosedOnAmbiguousProjectOnlyMatch(t *testing.T) {
	store := &Store{
		path: filepath.Join(t.TempDir(), "stacks.json"),
		stacks: map[string]Stack{
			"1": {
				ID:          "1",
				Name:        "shared-a",
				ProjectName: "shared",
			},
			"2": {
				ID:          "2",
				Name:        "shared-b",
				ProjectName: "shared",
			},
		},
	}

	if _, ok := store.FindForComposeTarget("shared", "", ""); ok {
		t.Fatal("FindForComposeTarget() matched ambiguous project without discriminator")
	}
}
