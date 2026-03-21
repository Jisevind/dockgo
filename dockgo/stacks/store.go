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

func (s *Store) FindByComposeProject(project string) (Stack, bool) {
	return s.FindForComposeTarget(project, "", "")
}

func (s *Store) GetByManagedContainer(containerID string) (Stack, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	containerID = strings.TrimSpace(containerID)
	if containerID == "" {
		return Stack{}, false
	}

	for _, stack := range s.stacks {
		for _, ownedID := range stack.ManagedContainers {
			if ownedID == containerID {
				return stack, true
			}
		}
	}

	return Stack{}, false
}

func (s *Store) FindForComposeTarget(project string, workingDir string, service string) (Stack, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	project = strings.TrimSpace(project)
	if project == "" {
		return Stack{}, false
	}

	projectMatches := make([]Stack, 0)
	for _, stack := range s.stacks {
		if stack.Discovery.ComposeProject == project || stack.ProjectName == project || stack.Name == project {
			projectMatches = append(projectMatches, stack)
		}
	}

	if len(projectMatches) == 0 {
		return Stack{}, false
	}
	if len(projectMatches) == 1 {
		return projectMatches[0], true
	}

	if workingDir = normalizeMatchPath(workingDir); workingDir != "" {
		exactWorkingDirMatches := make([]Stack, 0)
		for _, stack := range projectMatches {
			if normalizeMatchPath(stack.WorkingDir) == workingDir {
				exactWorkingDirMatches = append(exactWorkingDirMatches, stack)
			}
		}
		if len(exactWorkingDirMatches) == 1 {
			return exactWorkingDirMatches[0], true
		}
		if len(exactWorkingDirMatches) > 1 {
			projectMatches = exactWorkingDirMatches
		}
	}

	service = strings.TrimSpace(strings.ToLower(service))
	if service != "" {
		serviceMatches := make([]Stack, 0)
		for _, stack := range projectMatches {
			for _, serviceName := range stack.Discovery.ServiceNames {
				if strings.ToLower(strings.TrimSpace(serviceName)) == service {
					serviceMatches = append(serviceMatches, stack)
					break
				}
			}
		}
		if len(serviceMatches) == 1 {
			return serviceMatches[0], true
		}
	}

	return Stack{}, false
}

func normalizeMatchPath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.ReplaceAll(path, "\\", "/")
	path = strings.TrimRight(path, "/")
	return strings.ToLower(path)
}

func (s *Store) Save(stack Stack) (Stack, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	stack = normalizeStackForStorage(stack)

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

func (s *Store) RecordDeployStatus(id string, status string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	stack, ok := s.stacks[id]
	if !ok {
		return fmt.Errorf("stack not found")
	}

	stack.LastDeployStatus = status
	stack.LastDeployAt = &at
	stack.UpdatedAt = at
	s.stacks[id] = stack

	return s.persistLocked()
}

func (s *Store) RecordManagedContainers(id string, containerIDs []string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	stack, ok := s.stacks[id]
	if !ok {
		return fmt.Errorf("stack not found")
	}

	stack.ManagedContainers = append([]string(nil), uniqueStrings(containerIDs)...)
	stack.UpdatedAt = at
	s.stacks[id] = stack

	return s.persistLocked()
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
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
		stack = normalizeStackForStorage(stack)
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
