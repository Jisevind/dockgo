package agentstore

import (
	cryptorand "crypto/rand"
	"encoding/base64"
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
	"golang.org/x/crypto/bcrypt"
)

var storeLog = logger.WithSubsystem("agentstore")

// AgentStatus describes the current connection state of an agent.
type AgentStatus string

const (
	StatusOnline   AgentStatus = "online"
	StatusOffline  AgentStatus = "offline"
	StatusDisabled AgentStatus = "disabled"
)

// Agent is a registered remote Docker host record.
type Agent struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	Hostname  string      `json:"hostname,omitempty"`
	Version   string      `json:"version,omitempty"`
	KeyHash   string      `json:"key_hash"`
	Disabled  bool        `json:"disabled,omitempty"`
	LastSeen  time.Time   `json:"last_seen,omitempty"`
	Status    AgentStatus `json:"status,omitempty"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
}

// Store persists Agent records to a JSON file.
type Store struct {
	path  string
	mu    sync.RWMutex
	store map[string]Agent
}

// NewStore loads (or initializes) an agent store at the given path.
func NewStore(path string) (*Store, error) {
	s := &Store{
		path:  path,
		store: make(map[string]Agent),
	}

	if err := s.load(); err != nil {
		return nil, err
	}

	return s, nil
}

// GenerateKey creates a new agent API key. Only the bcrypt hash is ever stored.
func GenerateKey() (string, error) {
	raw := make([]byte, 32)
	if _, err := cryptorand.Read(raw); err != nil {
		return "", fmt.Errorf("failed to generate agent key: %w", err)
	}
	return "dg_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func hashKey(key string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(key), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash agent key: %w", err)
	}
	return string(hash), nil
}

// List returns all agents sorted by name.
func (s *Store) List() []Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]Agent, 0, len(s.store))
	for _, agent := range s.store {
		items = append(items, agent)
	}

	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})

	return items
}

// ListEnabled returns all non-disabled agents.
func (s *Store) ListEnabled() []Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]Agent, 0, len(s.store))
	for _, agent := range s.store {
		if agent.Disabled {
			continue
		}
		items = append(items, agent)
	}

	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})

	return items
}

// Get returns an agent by ID.
func (s *Store) Get(id string) (Agent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	agent, ok := s.store[id]
	return agent, ok
}

// GetByName returns an agent by name.
func (s *Store) GetByName(name string) (Agent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	name = strings.TrimSpace(name)
	for _, agent := range s.store {
		if strings.EqualFold(agent.Name, name) {
			return agent, true
		}
	}

	return Agent{}, false
}

// Create registers a new agent and returns the plaintext key exactly once.
// The store only persists the bcrypt hash of the key.
func (s *Store) Create(name string) (Agent, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	name = strings.TrimSpace(name)
	if name == "" {
		return Agent{}, "", fmt.Errorf("agent name is required")
	}

	for _, agent := range s.store {
		if strings.EqualFold(agent.Name, name) {
			return Agent{}, "", fmt.Errorf("agent with name %q already exists", name)
		}
	}

	key, err := GenerateKey()
	if err != nil {
		return Agent{}, "", err
	}

	hash, err := hashKey(key)
	if err != nil {
		return Agent{}, "", err
	}

	now := time.Now().UTC()
	agent := Agent{
		ID:        uuid.NewString(),
		Name:      name,
		KeyHash:   hash,
		Status:    StatusOffline,
		CreatedAt: now,
		UpdatedAt: now,
	}

	s.store[agent.ID] = agent

	if err := s.persistLocked(); err != nil {
		delete(s.store, agent.ID)
		return Agent{}, "", err
	}

	storeLog.Info("Agent created", logger.String("agent_id", agent.ID), logger.String("name", name))
	return agent, key, nil
}

// Update replaces mutable fields of an existing agent.
func (s *Store) Update(agent Agent) (Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.store[agent.ID]
	if !ok {
		return Agent{}, fmt.Errorf("agent not found")
	}

	agent.CreatedAt = existing.CreatedAt
	agent.KeyHash = existing.KeyHash
	agent.UpdatedAt = time.Now().UTC()
	if agent.Name == "" {
		agent.Name = existing.Name
	}
	if agent.Hostname == "" {
		agent.Hostname = existing.Hostname
	}

	s.store[agent.ID] = agent

	if err := s.persistLocked(); err != nil {
		return Agent{}, err
	}

	return agent, nil
}

// RecordSeen updates LastSeen and connection metadata for an agent.
func (s *Store) RecordSeen(id, hostname, version string) (Agent, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	agent, ok := s.store[id]
	if !ok {
		return Agent{}, false
	}

	now := time.Now().UTC()
	agent.LastSeen = now
	agent.Status = StatusOnline
	if hostname != "" {
		agent.Hostname = hostname
	}
	if version != "" {
		agent.Version = version
	}
	agent.UpdatedAt = now

	s.store[id] = agent

	if err := s.persistLocked(); err != nil {
		storeLog.Error("Failed to persist agent seen state",
			logger.String("agent_id", id),
			logger.Any("error", err),
		)
	}

	return agent, true
}

// MarkOffline sets the agent status to offline without touching LastSeen.
func (s *Store) MarkOffline(id string) (Agent, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	agent, ok := s.store[id]
	if !ok {
		return Agent{}, false
	}

	agent.Status = StatusOffline
	agent.UpdatedAt = time.Now().UTC()
	s.store[id] = agent

	if err := s.persistLocked(); err != nil {
		storeLog.Error("Failed to persist agent offline state",
			logger.String("agent_id", id),
			logger.Any("error", err),
		)
	}

	return agent, true
}

// Disable marks an agent as disabled. Disabled agents cannot connect.
func (s *Store) Disable(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	agent, ok := s.store[id]
	if !ok {
		return fmt.Errorf("agent not found")
	}

	agent.Disabled = true
	agent.Status = StatusDisabled
	agent.UpdatedAt = time.Now().UTC()
	s.store[id] = agent

	return s.persistLocked()
}

// Enable re-enables a previously disabled agent.
func (s *Store) Enable(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	agent, ok := s.store[id]
	if !ok {
		return fmt.Errorf("agent not found")
	}

	agent.Disabled = false
	agent.Status = StatusOffline
	agent.UpdatedAt = time.Now().UTC()
	s.store[id] = agent

	return s.persistLocked()
}

// RotateKey generates a fresh key for an agent and returns the plaintext key exactly once.
func (s *Store) RotateKey(id string) (Agent, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	agent, ok := s.store[id]
	if !ok {
		return Agent{}, "", fmt.Errorf("agent not found")
	}

	key, err := GenerateKey()
	if err != nil {
		return Agent{}, "", err
	}

	hash, err := hashKey(key)
	if err != nil {
		return Agent{}, "", err
	}

	agent.KeyHash = hash
	agent.UpdatedAt = time.Now().UTC()
	s.store[id] = agent

	if err := s.persistLocked(); err != nil {
		return Agent{}, "", err
	}

	storeLog.Info("Agent key rotated", logger.String("agent_id", id))
	return agent, key, nil
}

// Delete removes an agent record entirely.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.store[id]; !ok {
		return fmt.Errorf("agent not found")
	}

	delete(s.store, id)
	return s.persistLocked()
}

// CheckKey validates a plaintext key against the stored hash for an agent.
func (s *Store) CheckKey(id, key string) bool {
	s.mu.RLock()
	agent, ok := s.store[id]
	s.mu.RUnlock()

	if !ok || agent.KeyHash == "" || agent.Disabled {
		return false
	}

	if err := bcrypt.CompareHashAndPassword([]byte(agent.KeyHash), []byte(key)); err != nil {
		return false
	}

	return true
}

// CheckKeyByName resolves an agent by name and validates a plaintext key against it.
// Used during the initial handshake, when the agent has not learned its ID yet.
func (s *Store) CheckKeyByName(name, key string) (Agent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	name = strings.TrimSpace(name)
	for _, agent := range s.store {
		if !strings.EqualFold(agent.Name, name) {
			continue
		}
		if agent.Disabled || agent.KeyHash == "" {
			return Agent{}, false
		}
		if err := bcrypt.CompareHashAndPassword([]byte(agent.KeyHash), []byte(key)); err != nil {
			return Agent{}, false
		}
		return agent, true
	}

	return Agent{}, false
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read agent store: %w", err)
	}

	var payload struct {
		Agents []Agent `json:"agents"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("failed to decode agent store: %w", err)
	}

	for _, agent := range payload.Agents {
		s.store[agent.ID] = agent
	}

	storeLog.Info("Loaded registered agents", logger.Int("count", len(s.store)))
	return nil
}

func (s *Store) persistLocked() error {
	if dir := filepath.Dir(s.path); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create agent store directory: %w", err)
		}
	}

	payload := struct {
		Agents []Agent `json:"agents"`
	}{
		Agents: make([]Agent, 0, len(s.store)),
	}
	for _, agent := range s.store {
		payload.Agents = append(payload.Agents, agent)
	}

	sort.Slice(payload.Agents, func(i, j int) bool {
		return strings.ToLower(payload.Agents[i].Name) < strings.ToLower(payload.Agents[j].Name)
	})

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode agent store: %w", err)
	}

	tmpPath := s.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write temporary agent store: %w", err)
	}

	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("failed to commit agent store: %w", err)
	}

	return nil
}
