package agentstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "agents.json"))
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	return store
}

func TestGenerateKeyFormat(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if !strings.HasPrefix(key, "dg_") {
		t.Fatalf("GenerateKey() = %q, want prefix dg_", key)
	}
	if len(key) != len("dg_")+43 {
		t.Fatalf("GenerateKey() = %q, unexpected length %d", key, len(key))
	}

	key2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if key == key2 {
		t.Fatal("GenerateKey() returned the same key twice")
	}
}

func TestStoreCreateReturnsKeyOnceAndPersists(t *testing.T) {
	store := newTestStore(t)

	agent, key, err := store.Create("host-a")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if agent.ID == "" {
		t.Fatal("Create() returned empty agent ID")
	}
	if key == "" || !strings.HasPrefix(key, "dg_") {
		t.Fatalf("Create() returned invalid key %q", key)
	}

	// The plaintext key must never be persisted.
	data := mustReadStoreFile(t, store.path)
	if strings.Contains(string(data), key) {
		t.Fatal("plaintext key found in persisted store")
	}

	// Reload from disk and verify the key still validates.
	reloaded, err := NewStore(store.path)
	if err != nil {
		t.Fatalf("NewStore(reload) error = %v", err)
	}
	if !reloaded.CheckKey(agent.ID, key) {
		t.Fatal("CheckKey() = false after reload, want true")
	}
	if reloaded.CheckKey(agent.ID, "wrong-key") {
		t.Fatal("CheckKey() with wrong key = true, want false")
	}
}

func TestStoreDuplicateNameRejected(t *testing.T) {
	store := newTestStore(t)

	if _, _, err := store.Create("dup"); err != nil {
		t.Fatalf("Create(dup) error = %v", err)
	}
	if _, _, err := store.Create("DUP"); err == nil {
		t.Fatal("Create(DUP) succeeded, want duplicate name rejection")
	}
}

func TestStoreCRUD(t *testing.T) {
	store := newTestStore(t)

	agent, _, err := store.Create("alpha")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if got, ok := store.Get(agent.ID); !ok || got.Name != "alpha" {
		t.Fatalf("Get() = %+v, %v", got, ok)
	}
	if got, ok := store.GetByName("ALPHA"); !ok || got.ID != agent.ID {
		t.Fatalf("GetByName() = %+v, %v", got, ok)
	}

	updated, err := store.Update(Agent{ID: agent.ID, Name: "alpha-renamed"})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if updated.Name != "alpha-renamed" {
		t.Fatalf("Update() name = %q, want alpha-renamed", updated.Name)
	}

	if err := store.Delete(agent.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, ok := store.Get(agent.ID); ok {
		t.Fatal("Get() after Delete() returned a record")
	}
}

func TestStoreDisableBlocksCheckKey(t *testing.T) {
	store := newTestStore(t)

	agent, key, err := store.Create("host-b")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !store.CheckKey(agent.ID, key) {
		t.Fatal("CheckKey() = false before disable, want true")
	}

	if err := store.Disable(agent.ID); err != nil {
		t.Fatalf("Disable() error = %v", err)
	}
	if store.CheckKey(agent.ID, key) {
		t.Fatal("CheckKey() = true for disabled agent, want false")
	}

	if err := store.Enable(agent.ID); err != nil {
		t.Fatalf("Enable() error = %v", err)
	}
	enabled, ok := store.Get(agent.ID)
	if !ok || enabled.Status != StatusOffline {
		t.Fatalf("after Enable() status = %q, want offline", enabled.Status)
	}
	if !store.CheckKey(agent.ID, key) {
		t.Fatal("CheckKey() = false after enable, want true")
	}
}

func TestStoreRotateKey(t *testing.T) {
	store := newTestStore(t)

	agent, oldKey, err := store.Create("host-c")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	_, newKey, err := store.RotateKey(agent.ID)
	if err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}
	if newKey == oldKey {
		t.Fatal("RotateKey() returned the same key")
	}

	if store.CheckKey(agent.ID, oldKey) {
		t.Fatal("CheckKey(oldKey) = true after rotation, want false")
	}
	if !store.CheckKey(agent.ID, newKey) {
		t.Fatal("CheckKey(newKey) = false after rotation, want true")
	}
}

func TestStoreHashMismatch(t *testing.T) {
	store := newTestStore(t)

	agent, _, err := store.Create("host-d")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Tamper with the stored hash and ensure CheckKey fails safely.
	store.mu.Lock()
	stored := store.store[agent.ID]
	stored.KeyHash = "$2a$10$invalidhash"
	store.store[agent.ID] = stored
	store.mu.Unlock()

	if store.CheckKey(agent.ID, "anything") {
		t.Fatal("CheckKey() with corrupted hash = true, want false")
	}
}

func TestStoreRecordSeenAndMarkOffline(t *testing.T) {
	store := newTestStore(t)

	agent, _, err := store.Create("host-e")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	seen, ok := store.RecordSeen(agent.ID, "host-e.example.com", "v1.2.3")
	if !ok {
		t.Fatal("RecordSeen() = false, want true")
	}
	if seen.Hostname != "host-e.example.com" || seen.Version != "v1.2.3" {
		t.Fatalf("RecordSeen() = %+v, want hostname/version updated", seen)
	}
	if seen.Status != StatusOnline {
		t.Fatalf("RecordSeen() status = %q, want online", seen.Status)
	}
	if seen.LastSeen.Before(time.Now().Add(-time.Minute)) {
		t.Fatal("RecordSeen() LastSeen not updated")
	}

	offline, ok := store.MarkOffline(agent.ID)
	if !ok {
		t.Fatal("MarkOffline() = false, want true")
	}
	if offline.Status != StatusOffline {
		t.Fatalf("MarkOffline() status = %q, want offline", offline.Status)
	}
}

func TestStoreListSortsByName(t *testing.T) {
	store := newTestStore(t)

	for _, name := range []string{"zulu", "alpha", "Mike"} {
		if _, _, err := store.Create(name); err != nil {
			t.Fatalf("Create(%s) error = %v", name, err)
		}
	}

	items := store.List()
	if len(items) != 3 {
		t.Fatalf("List() length = %d, want 3", len(items))
	}
	if items[0].Name != "alpha" || items[1].Name != "Mike" || items[2].Name != "zulu" {
		t.Fatalf("List() order = %v, want alpha, Mike, zulu", []string{items[0].Name, items[1].Name, items[2].Name})
	}
}

func mustReadStoreFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%s) error = %v", path, err)
	}
	return data
}
