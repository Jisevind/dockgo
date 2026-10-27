package server

import (
	"reflect"
	"testing"
)

func TestOverlayAgentUpdatesPreservesOtherEntriesAndPrunesStale(t *testing.T) {
	srv := &Server{
		agentUpdatesCache: map[string]map[string]bool{
			"agent-1": {
				"c1":   true,
				"c2":   true,
				"gone": true,
			},
		},
	}

	containers := []map[string]any{
		{"id": "c1"},
		{"id": "c2"},
		{"id": "c3"},
	}

	srv.overlayAgentUpdates("agent-1", containers)

	if containers[0]["update_available"] != true {
		t.Fatalf("c1 update_available = %v, want true", containers[0]["update_available"])
	}
	if containers[1]["update_available"] != true {
		t.Fatalf("c2 update_available = %v, want true", containers[1]["update_available"])
	}
	if _, ok := containers[2]["update_available"]; ok {
		t.Fatalf("c3 update_available = %v, want absent", containers[2]["update_available"])
	}

	wantCache := map[string]bool{"c1": true, "c2": true}
	if got := srv.agentUpdatesCache["agent-1"]; !reflect.DeepEqual(got, wantCache) {
		t.Fatalf("agent cache = %#v, want %#v", got, wantCache)
	}
}
