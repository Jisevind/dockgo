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

type HistoryEntry struct {
	ID        string    `json:"id"`
	StackID   string    `json:"stack_id"`
	StackName string    `json:"stack_name"`
	Action    string    `json:"action"`
	Status    string    `json:"status"`
	Message   string    `json:"message,omitempty"`
	CreatedAt time.Time `json:"created_at"`
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

	s.entries = append(s.entries, entry)
	if len(s.entries) > 500 {
		s.entries = s.entries[len(s.entries)-500:]
	}

	return s.persistLocked()
}

func (s *HistoryStore) ListByStack(stackID string, limit int) []HistoryEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	filtered := make([]HistoryEntry, 0)
	for _, entry := range s.entries {
		if entry.StackID == stackID {
			filtered = append(filtered, entry)
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].CreatedAt.After(filtered[j].CreatedAt)
	})

	if limit > 0 && len(filtered) > limit {
		filtered = filtered[:limit]
	}

	return filtered
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
