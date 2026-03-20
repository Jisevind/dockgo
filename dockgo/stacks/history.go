package stacks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	maxHistoryEntries         = 500
	maxPriorityHistoryEntries = 300
)

var priorityHistoryActions = map[string]struct{}{
	"deploy":  {},
	"pull":    {},
	"restart": {},
	"down":    {},
}

type HistoryEntry struct {
	ID          string    `json:"id"`
	StackID     string    `json:"stack_id"`
	StackName   string    `json:"stack_name"`
	Action      string    `json:"action"`
	Status      string    `json:"status"`
	Source      string    `json:"source,omitempty"`
	Message     string    `json:"message,omitempty"`
	Details     []string  `json:"details,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	StartedAt   time.Time `json:"started_at,omitempty"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
	DurationMs  int64     `json:"duration_ms,omitempty"`
}

type HistoryFilter struct {
	Action string
	Status string
	Source string
	Limit  int
}

type HistorySummary struct {
	LastEvent            *HistoryEntry `json:"last_event,omitempty"`
	LastSuccessfulDeploy *HistoryEntry `json:"last_successful_deploy,omitempty"`
	LastFailedAction     *HistoryEntry `json:"last_failed_action,omitempty"`
	LastDashboardDeploy  *HistoryEntry `json:"last_dashboard_deploy,omitempty"`
	LastStacksViewAction *HistoryEntry `json:"last_stacks_view_action,omitempty"`
	LastSystemEvent      *HistoryEntry `json:"last_system_event,omitempty"`
}

type HistoryStore struct {
	path    string
	mu      sync.RWMutex
	entries []HistoryEntry
}

func NewHistoryStore(path string) (*HistoryStore, error) {
	s := &HistoryStore{path: path, entries: make([]HistoryEntry, 0)}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *HistoryStore) Append(entry HistoryEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry.ID == "" {
		entry.ID = fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	if entry.StartedAt.IsZero() {
		entry.StartedAt = entry.CreatedAt
	}
	if entry.CompletedAt.IsZero() {
		entry.CompletedAt = entry.CreatedAt
	}
	if entry.DurationMs == 0 && !entry.CompletedAt.Before(entry.StartedAt) {
		entry.DurationMs = entry.CompletedAt.Sub(entry.StartedAt).Milliseconds()
	}

	s.entries = append(s.entries, entry)
	if len(s.entries) > maxHistoryEntries {
		s.entries = pruneHistoryEntries(s.entries)
	}

	return s.persistLocked()
}

func pruneHistoryEntries(entries []HistoryEntry) []HistoryEntry {
	if len(entries) <= maxHistoryEntries {
		return entries
	}

	sorted := append([]HistoryEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].CreatedAt.After(sorted[j].CreatedAt)
	})

	kept := make([]HistoryEntry, 0, maxHistoryEntries)
	priorityCount := 0

	for _, entry := range sorted {
		if isPriorityHistoryEntry(entry) && priorityCount < maxPriorityHistoryEntries {
			kept = append(kept, entry)
			priorityCount++
		}
		if len(kept) == maxHistoryEntries {
			break
		}
	}

	for _, entry := range sorted {
		if len(kept) == maxHistoryEntries {
			break
		}
		if containsHistoryEntry(kept, entry.ID, entry.CreatedAt) {
			continue
		}
		kept = append(kept, entry)
	}

	sort.Slice(kept, func(i, j int) bool {
		return kept[i].CreatedAt.Before(kept[j].CreatedAt)
	})
	return kept
}

func isPriorityHistoryEntry(entry HistoryEntry) bool {
	if entry.Status == "error" {
		return true
	}
	_, ok := priorityHistoryActions[entry.Action]
	return ok
}

func containsHistoryEntry(entries []HistoryEntry, id string, createdAt time.Time) bool {
	for _, entry := range entries {
		if id != "" && entry.ID == id {
			return true
		}
		if id == "" && entry.CreatedAt.Equal(createdAt) {
			return true
		}
	}
	return false
}

func (s *HistoryStore) ListByStack(stackID string, limit int) []HistoryEntry {
	return s.ListByStackFiltered(stackID, HistoryFilter{Limit: limit})
}

func (s *HistoryStore) ListByStackFiltered(stackID string, filter HistoryFilter) []HistoryEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	filtered := make([]HistoryEntry, 0)
	for _, entry := range s.entries {
		if entry.StackID != stackID {
			continue
		}
		if filter.Action != "" && entry.Action != filter.Action {
			continue
		}
		if filter.Status != "" && entry.Status != filter.Status {
			continue
		}
		if filter.Source != "" && entry.Source != filter.Source {
			continue
		}
		filtered = append(filtered, entry)
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].CreatedAt.After(filtered[j].CreatedAt)
	})

	if filter.Limit > 0 && len(filtered) > filter.Limit {
		filtered = filtered[:filter.Limit]
	}

	return filtered
}

func (s *HistoryStore) SummarizeByStack(stackID string) HistorySummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries := make([]HistoryEntry, 0)
	for _, entry := range s.entries {
		if entry.StackID == stackID {
			entries = append(entries, entry)
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].CreatedAt.After(entries[j].CreatedAt)
	})

	summary := HistorySummary{}
	for _, entry := range entries {
		entryCopy := entry

		if summary.LastEvent == nil {
			summary.LastEvent = &entryCopy
		}
		if summary.LastSuccessfulDeploy == nil && entry.Action == "deploy" && entry.Status == "success" {
			summary.LastSuccessfulDeploy = &entryCopy
		}
		if summary.LastFailedAction == nil && entry.Status == "error" {
			summary.LastFailedAction = &entryCopy
		}
		if summary.LastDashboardDeploy == nil && entry.Action == "deploy" && entry.Source == "dashboard_update" {
			summary.LastDashboardDeploy = &entryCopy
		}
		if summary.LastStacksViewAction == nil && entry.Source == "stacks_view" {
			summary.LastStacksViewAction = &entryCopy
		}
		if summary.LastSystemEvent == nil && entry.Source == "system" {
			summary.LastSystemEvent = &entryCopy
		}
	}

	return summary
}

func (s *HistoryStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read stack history store: %w", err)
	}

	var payload struct {
		Entries []HistoryEntry `json:"entries"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("failed to decode stack history store: %w", err)
	}

	s.entries = payload.Entries
	return nil
}

func (s *HistoryStore) persistLocked() error {
	if dir := filepath.Dir(s.path); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create stack history directory: %w", err)
		}
	}

	payload := struct {
		Entries []HistoryEntry `json:"entries"`
	}{
		Entries: s.entries,
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode stack history store: %w", err)
	}

	tmpPath := s.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write temporary stack history store: %w", err)
	}

	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("failed to commit stack history store: %w", err)
	}

	return nil
}
