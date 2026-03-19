package stacks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"dockgo/logger"

	"github.com/google/uuid"
)

var stacksLog = logger.WithSubsystem("stacks")

type Store struct {
	path   string
	mu     sync.RWMutex
	stacks map[string]Stack
}

func NewStore(path string) (*Store, error) {
	s := &Store{
		path:   path,
		stacks: make(map[string]Stack),
	}

	if err := s.load(); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Store) List() []Stack {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]Stack, 0, len(s.stacks))
	for _, stack := range s.stacks {
		items = append(items, stack)
	}

	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})

	return items
}

func (s *Store) Get(id string) (Stack, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stack, ok := s.stacks[id]
	return stack, ok
}

func (s *Store) Save(stack Stack) (Stack, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()

	if stack.ID == "" {
		stack.ID = uuid.NewString()
		stack.CreatedAt = now
	} else if existing, ok := s.stacks[stack.ID]; ok {
		stack.CreatedAt = existing.CreatedAt
	} else if stack.CreatedAt.IsZero() {
		stack.CreatedAt = now
	}

	stack.Name = strings.TrimSpace(stack.Name)
	stack.ProjectName = strings.TrimSpace(stack.ProjectName)
	stack.WorkingDir = strings.TrimSpace(stack.WorkingDir)
	stack.UpdatedAt = now

	if stack.UpdatePolicy == (UpdatePolicy{}) {
		stack.UpdatePolicy = DefaultUpdatePolicy()
	}
	if stack.HealthPolicy == (HealthPolicy{}) {
		stack.HealthPolicy = DefaultHealthPolicy()
	}

	s.stacks[stack.ID] = stack

	if err := s.persistLocked(); err != nil {
		return Stack{}, err
	}

	return stack, nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.stacks[id]; !ok {
		return fmt.Errorf("stack not found")
	}

	delete(s.stacks, id)
	return s.persistLocked()
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read stack store: %w", err)
	}

	var payload struct {
		Stacks []Stack `json:"stacks"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("failed to decode stack store: %w", err)
	}

	for _, stack := range payload.Stacks {
		s.stacks[stack.ID] = stack
	}

	stacksLog.Info("Loaded registered stacks", logger.Int("count", len(s.stacks)))
	return nil
}

func (s *Store) persistLocked() error {
	if dir := filepath.Dir(s.path); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create stack store directory: %w", err)
		}
	}

	payload := struct {
		Stacks []Stack `json:"stacks"`
	}{
		Stacks: make([]Stack, 0, len(s.stacks)),
	}
	for _, stack := range s.stacks {
		payload.Stacks = append(payload.Stacks, stack)
	}

	sort.Slice(payload.Stacks, func(i, j int) bool {
		return strings.ToLower(payload.Stacks[i].Name) < strings.ToLower(payload.Stacks[j].Name)
	})

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode stack store: %w", err)
	}

	tmpPath := s.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write temporary stack store: %w", err)
	}

	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("failed to commit stack store: %w", err)
	}

	return nil
}
