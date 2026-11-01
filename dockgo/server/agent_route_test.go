package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAgentRouteRewritePreservesAgentID(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/agent/a1/volumes/prune", nil)
	rewritten := rewriteAgentRoute(r, "a1", "volumes/prune")
	if got, ok := agentQueryAgentID(rewritten); !ok || got != "a1" {
		t.Fatalf("agent id = %q, %v; want a1", got, ok)
	}
	if rewritten.URL.Path != "/api/volumes/prune" {
		t.Fatalf("path = %q", rewritten.URL.Path)
	}
}

func TestAgentRouteSelectsExactRoutes(t *testing.T) {
	cases := map[string]string{
		"volumes/prune":    "volumes-prune",
		"images/prune":     "images-prune",
		"stacks/overview":  "stacks-overview",
		"volumes/data":     "volume-detail",
		"images/abc":       "image-detail",
		"networks/bridge":  "network-detail",
		"stacks/some-uuid": "stacks",
	}
	for rest, want := range cases {
		if got := agentRouteName(rest); got != want {
			t.Errorf("agentRouteName(%q) = %q, want %q", rest, got, want)
		}
	}
}
