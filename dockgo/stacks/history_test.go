package stacks

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestHistoryStoreListByStackFiltered(t *testing.T) {
	store := &HistoryStore{
		path: filepath.Join(t.TempDir(), "history.json"),
		entries: []HistoryEntry{
			{
				StackID:   "stack-1",
				Action:    "deploy",
				Status:    "success",
				Source:    "dashboard_update",
				CreatedAt: time.Date(2026, 3, 20, 10, 0, 0, 0, time.UTC),
			},
			{
				StackID:   "stack-1",
				Action:    "deploy",
				Status:    "error",
				Source:    "stacks_view",
				CreatedAt: time.Date(2026, 3, 20, 11, 0, 0, 0, time.UTC),
			},
			{
				StackID:   "stack-1",
				Action:    "edit",
				Status:    "success",
				Source:    "system",
				CreatedAt: time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC),
			},
			{
				StackID:   "stack-2",
				Action:    "deploy",
				Status:    "success",
				Source:    "dashboard_update",
				CreatedAt: time.Date(2026, 3, 20, 13, 0, 0, 0, time.UTC),
			},
		},
	}

	got := store.ListByStackFiltered("stack-1", HistoryFilter{
		Action: "deploy",
		Status: "success",
		Source: "dashboard_update",
		Limit:  5,
	})

	if len(got) != 1 {
		t.Fatalf("ListByStackFiltered() len = %d, want 1", len(got))
	}
	if got[0].Action != "deploy" || got[0].Status != "success" || got[0].Source != "dashboard_update" {
		t.Fatalf("unexpected filtered entry: %+v", got[0])
	}
}

func TestHistoryStoreSummarizeByStack(t *testing.T) {
	store := &HistoryStore{
		path: filepath.Join(t.TempDir(), "history.json"),
		entries: []HistoryEntry{
			{
				StackID:   "stack-1",
				Action:    "edit",
				Status:    "success",
				Source:    "system",
				CreatedAt: time.Date(2026, 3, 20, 9, 0, 0, 0, time.UTC),
			},
			{
				StackID:   "stack-1",
				Action:    "deploy",
				Status:    "success",
				Source:    "dashboard_update",
				CreatedAt: time.Date(2026, 3, 20, 10, 0, 0, 0, time.UTC),
			},
			{
				StackID:   "stack-1",
				Action:    "restart",
				Status:    "error",
				Source:    "stacks_view",
				CreatedAt: time.Date(2026, 3, 20, 11, 0, 0, 0, time.UTC),
			},
			{
				StackID:   "stack-1",
				Action:    "pull",
				Status:    "success",
				Source:    "stacks_view",
				CreatedAt: time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC),
			},
		},
	}

	summary := store.SummarizeByStack("stack-1")

	if summary.LastEvent == nil || summary.LastEvent.Action != "pull" {
		t.Fatalf("LastEvent = %+v, want pull", summary.LastEvent)
	}
	if summary.LastSuccessfulDeploy == nil || summary.LastSuccessfulDeploy.Source != "dashboard_update" {
		t.Fatalf("LastSuccessfulDeploy = %+v, want dashboard_update deploy", summary.LastSuccessfulDeploy)
	}
	if summary.LastFailedAction == nil || summary.LastFailedAction.Action != "restart" {
		t.Fatalf("LastFailedAction = %+v, want restart error", summary.LastFailedAction)
	}
	if summary.LastDashboardDeploy == nil || summary.LastDashboardDeploy.Action != "deploy" {
		t.Fatalf("LastDashboardDeploy = %+v, want deploy", summary.LastDashboardDeploy)
	}
	if summary.LastStacksViewAction == nil || summary.LastStacksViewAction.Action != "pull" {
		t.Fatalf("LastStacksViewAction = %+v, want pull", summary.LastStacksViewAction)
	}
	if summary.LastSystemEvent == nil || summary.LastSystemEvent.Action != "edit" {
		t.Fatalf("LastSystemEvent = %+v, want edit", summary.LastSystemEvent)
	}
}

func TestPruneHistoryEntriesPrioritizesOperationalEvents(t *testing.T) {
	base := time.Date(2026, 3, 20, 0, 0, 0, 0, time.UTC)
	entries := make([]HistoryEntry, 0, maxHistoryEntries+50)

	for i := 0; i < maxHistoryEntries; i++ {
		entries = append(entries, HistoryEntry{
			ID:        fmt.Sprintf("routine-%03d", i),
			StackID:   "stack-1",
			Action:    "edit",
			Status:    "success",
			CreatedAt: base.Add(time.Duration(i) * time.Minute),
		})
	}

	for i := 0; i < 25; i++ {
		entries = append(entries, HistoryEntry{
			ID:        fmt.Sprintf("deploy-%02d", i),
			StackID:   "stack-1",
			Action:    "deploy",
			Status:    "success",
			CreatedAt: base.Add(time.Duration(maxHistoryEntries+i) * time.Minute),
		})
	}

	for i := 0; i < 25; i++ {
		entries = append(entries, HistoryEntry{
			ID:        fmt.Sprintf("error-%02d", i),
			StackID:   "stack-1",
			Action:    "validate",
			Status:    "error",
			CreatedAt: base.Add(time.Duration(maxHistoryEntries+25+i) * time.Minute),
		})
	}

	pruned := pruneHistoryEntries(entries)

	if len(pruned) != maxHistoryEntries {
		t.Fatalf("pruneHistoryEntries() len = %d, want %d", len(pruned), maxHistoryEntries)
	}

	for i := 0; i < 25; i++ {
		if !historyEntryExists(pruned, fmt.Sprintf("deploy-%02d", i)) {
			t.Fatalf("expected deploy-%02d to be retained", i)
		}
		if !historyEntryExists(pruned, fmt.Sprintf("error-%02d", i)) {
			t.Fatalf("expected error-%02d to be retained", i)
		}
	}

	if historyEntryExists(pruned, "routine-000") {
		t.Fatalf("expected oldest routine entry to be pruned")
	}
}

func TestPruneHistoryEntriesKeepsUniqueEntriesWithoutIDs(t *testing.T) {
	base := time.Date(2026, 3, 20, 0, 0, 0, 0, time.UTC)
	entries := make([]HistoryEntry, 0, maxHistoryEntries+1)

	for i := 0; i < maxHistoryEntries+1; i++ {
		entries = append(entries, HistoryEntry{
			StackID:   "stack-1",
			Action:    "edit",
			Status:    "success",
			CreatedAt: base.Add(time.Duration(i) * time.Minute),
		})
	}

	pruned := pruneHistoryEntries(entries)

	if len(pruned) != maxHistoryEntries {
		t.Fatalf("pruneHistoryEntries() len = %d, want %d", len(pruned), maxHistoryEntries)
	}

	if !pruned[0].CreatedAt.Equal(base.Add(1 * time.Minute)) {
		t.Fatalf("expected oldest entry to be pruned, first retained = %s", pruned[0].CreatedAt)
	}
	if !pruned[len(pruned)-1].CreatedAt.Equal(base.Add(maxHistoryEntries * time.Minute)) {
		t.Fatalf("expected newest entry to be retained, last retained = %s", pruned[len(pruned)-1].CreatedAt)
	}
}

func historyEntryExists(entries []HistoryEntry, id string) bool {
	for _, entry := range entries {
		if entry.ID == id {
			return true
		}
	}
	return false
}
