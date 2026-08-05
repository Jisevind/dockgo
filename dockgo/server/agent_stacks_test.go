package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"dockgo/agent"
	"dockgo/agentmanager"
	"dockgo/agentstore"
	"dockgo/stacks"

	"github.com/coder/websocket"
)

// newTestServerWithAgent wires a server with an agent store, manager, and a
// registered fake agent channel.
func newTestServerWithAgent(t *testing.T) (*Server, *agentmanager.Manager) {
	t.Helper()

	agentStore, err := agentstore.NewStore(filepath.Join(t.TempDir(), "agents.json"))
	if err != nil {
		t.Fatalf("agentstore.NewStore() error = %v", err)
	}
	if _, _, err := agentStore.Create("remote-host"); err != nil {
		t.Fatalf("agentStore.Create() error = %v", err)
	}

	store, err := stacks.NewStore(filepath.Join(t.TempDir(), "stacks.json"))
	if err != nil {
		t.Fatalf("stacks.NewStore() error = %v", err)
	}
	history, err := stacks.NewHistoryStore(filepath.Join(t.TempDir(), "stack_history.json"))
	if err != nil {
		t.Fatalf("stacks.NewHistoryStore() error = %v", err)
	}

	mgr, err := agentmanager.New(agentmanager.Config{
		Store:         agentStore,
		JWTSecret:     "test-secret-for-agent-manager",
		MaxConcurrent: 8,
	})
	if err != nil {
		t.Fatalf("agentmanager.New() error = %v", err)
	}

	srv := &Server{
		StackStore:       store,
		StackHistory:     history,
		AgentStore:       agentStore,
		AgentManager:     mgr,
		loginAttempts:    make(map[string]*RateLimiter),
		agentRegAttempts: make(map[string]*RateLimiter),
	}

	return srv, mgr
}

func TestAgentStackRouteRejectsLocalStack(t *testing.T) {
	srv, _ := newTestServerWithAgent(t)

	localStack, err := srv.StackStore.Save(stacks.Stack{
		Name:         "local",
		ProjectName:  "local-proj",
		WorkingDir:   t.TempDir(),
		ComposeFiles: []string{filepath.Join(t.TempDir(), "compose.yaml")},
		PathMode:     stacks.PathModeHostNative,
	})
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/stacks/"+localStack.ID+"?agent=some-agent", nil)
	rr := httptest.NewRecorder()
	srv.handleStackByID(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for local stack via agent route", rr.Code)
	}
}

func TestAgentStackRouteNotFoundForWrongAgent(t *testing.T) {
	srv, _ := newTestServerWithAgent(t)

	agentStack, err := srv.StackStore.Save(stacks.Stack{
		Name:         "remote",
		ProjectName:  "remote-proj",
		WorkingDir:   "/opt/stacks/remote",
		ComposeFiles: []string{"/opt/stacks/remote/compose.yaml"},
		PathMode:     stacks.PathModeHostNative,
		AgentID:      "agent-a",
	})
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Querying for a different agent must not expose the stack.
	req := httptest.NewRequest(http.MethodGet, "/api/stacks/"+agentStack.ID+"?agent=agent-b", nil)
	rr := httptest.NewRecorder()
	srv.handleStackByID(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for mismatched agent", rr.Code)
	}
}

func TestAgentStackCreateRejectsGitKind(t *testing.T) {
	srv, _ := newTestServerWithAgent(t)

	payload := map[string]any{
		"name":          "git-stack",
		"project_name":  "git-proj",
		"kind":          "git_repo",
		"working_dir":   "/tmp",
		"compose_files": []string{"/tmp/compose.yaml"},
		"git_source": map[string]any{
			"repo_url": "https://example.com/repo.git",
		},
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/stacks?agent=agent-a", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	srv.handleStacks(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for git-kind agent stack", rr.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !bytes.Contains([]byte(resp["error"].(string)), []byte("git")) {
		t.Fatalf("error = %q, want git-kind rejection message", resp["error"])
	}
}

func TestAgentStackListFiltersByAgent(t *testing.T) {
	srv, _ := newTestServerWithAgent(t)

	if _, err := srv.StackStore.Save(stacks.Stack{
		Name:         "agent-stack",
		ProjectName:  "agent-proj",
		WorkingDir:   "/opt/stacks/agent",
		ComposeFiles: []string{"/opt/stacks/agent/compose.yaml"},
		PathMode:     stacks.PathModeHostNative,
		AgentID:      "agent-a",
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if _, err := srv.StackStore.Save(stacks.Stack{
		Name:         "local-stack",
		ProjectName:  "local-proj",
		WorkingDir:   t.TempDir(),
		ComposeFiles: []string{filepath.Join(t.TempDir(), "compose.yaml")},
		PathMode:     stacks.PathModeHostNative,
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/stacks?agent=agent-a", nil)
	rr := httptest.NewRecorder()
	srv.handleStacks(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}

	var resp struct {
		Stacks []struct {
			Stack stacks.Stack `json:"stack"`
		} `json:"stacks"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if len(resp.Stacks) != 1 {
		t.Fatalf("stack count = %d, want 1 (agent-filtered)", len(resp.Stacks))
	}
	if resp.Stacks[0].Stack.AgentID != "agent-a" {
		t.Fatalf("stack agent_id = %q, want agent-a", resp.Stacks[0].Stack.AgentID)
	}
}

func TestAgentStackRegisteredScopedToAgent(t *testing.T) {
	srv, _ := newTestServerWithAgent(t)

	// A stack registered for agent-a on this project.
	if _, err := srv.StackStore.Save(stacks.Stack{
		Name:         "agent-a-registry",
		ProjectName:  "registry",
		WorkingDir:   "/compose/registry",
		ComposeFiles: []string{"/compose/registry/compose.yml"},
		PathMode:     stacks.PathModeHostNative,
		AgentID:      "agent-a",
		Discovery: stacks.DiscoverySelector{
			ComposeProject: "registry",
			ServiceNames:   []string{"registry", "registry-ui"},
		},
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// A different stack registered for agent-b on the same project.
	if _, err := srv.StackStore.Save(stacks.Stack{
		Name:         "agent-b-registry",
		ProjectName:  "registry",
		WorkingDir:   "/compose/registry",
		ComposeFiles: []string{"/compose/registry/compose.yml"},
		PathMode:     stacks.PathModeHostNative,
		AgentID:      "agent-b",
		Discovery: stacks.DiscoverySelector{
			ComposeProject: "registry",
			ServiceNames:   []string{"registry", "registry-ui"},
		},
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Discovery for agent-a should see the project as registered.
	if !srv.agentStackRegistered("agent-a", "registry", "/compose/registry", []string{"registry"}) {
		t.Fatal("agent-a discovery should report registry as registered")
	}

	// A project that has no stack for agent-a must report unregistered.
	if srv.agentStackRegistered("agent-a", "registry", "/compose/other", []string{"other"}) {
		t.Fatal("agent-a discovery for an unregistered working dir should report unregistered")
	}

	// Local host discovery (empty agent id) must not pick up agent stacks.
	if srv.agentStackRegistered("", "registry", "/compose/registry", []string{"registry"}) {
		t.Fatal("local discovery must not report an agent-owned stack as registered")
	}
}

func TestAgentStackRegisteredMatchesMappedPath(t *testing.T) {
	srv, _ := newTestServerWithAgent(t)

	if _, err := srv.StackStore.Save(stacks.Stack{
		Name:         "mapped-registry",
		ProjectName:  "registry",
		WorkingDir:   "D:\\Docker\\registry",
		ComposeFiles: []string{"D:\\Docker\\registry\\compose.yml"},
		PathMode:     stacks.PathModeMapped,
		PathMappings: []stacks.PathMapping{{HostPath: "D:\\Docker", ContainerPath: "/compose"}},
		AgentID:      "agent-a",
		Discovery: stacks.DiscoverySelector{
			ComposeProject: "registry",
			ServiceNames:   []string{"registry"},
		},
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Agent runtime sees the mapped path, the store holds the host path.
	if !srv.agentStackRegistered("agent-a", "registry", "/compose/registry", []string{"registry"}) {
		t.Fatal("mapped-path stack should be detected as registered via runtime path")
	}
}

// connectTestAgent opens a websocket agent connection against the test server
// and performs the register handshake for an existing agent record, returning
// the client-side connection and context.
func connectTestAgent(t *testing.T, srv *Server, mux http.Handler, agentRec agentstore.Agent) (*websocket.Conn, context.Context) {
	t.Helper()

	_, key, err := srv.AgentStore.RotateKey(agentRec.ID)
	if err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	wsURL := "ws" + server.URL[len("http"):] + "/api/ws/agent"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	conn, resp, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("websocket.Dial() error = %v (status %d)", err, resp.StatusCode)
	}
	t.Cleanup(func() { _ = conn.Close(websocket.StatusNormalClosure, "done") })

	regEnv, _ := agent.NewEnvelope(agent.TypeRegister, "", agent.RegisterRequest{
		Key:      key,
		Hostname: agentRec.Name + ".example.com",
		Version:  "test",
		Name:     agentRec.Name,
	})
	regBytes, _ := regEnv.Marshal()
	if err := conn.Write(ctx, websocket.MessageText, regBytes); err != nil {
		t.Fatalf("conn.Write(register) error = %v", err)
	}

	_, _, err = conn.Read(ctx)
	if err != nil {
		t.Fatalf("conn.Read(welcome) error = %v", err)
	}

	return conn, ctx
}

func TestAgentStackCreateAutoBindsOwnership(t *testing.T) {
	srv, _ := newTestServerWithAgent(t)
	mux := srv.agentTestMux()

	agentRec, _, err := srv.AgentStore.Create("auto-bind")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	conn, ctx := connectTestAgent(t, srv, mux, agentRec)
	if !srv.AgentManager.IsOnline(agentRec.ID) {
		t.Fatal("agent not online after handshake")
	}

	// Drive handleStackByID (agent route) in a goroutine; it dispatches a
	// stack_validate request first, then a stack_containers request to bind
	// ownership of any matching runtime containers.
	payload := map[string]any{
		"name":           "dockgo",
		"project_name":   "dockgo",
		"kind":           "compose_files",
		"working_dir":    "D:\\code\\workspace\\dockgo",
		"compose_files":  []string{"D:\\code\\workspace\\dockgo\\docker-compose.yml"},
		"path_mode":      "mapped",
		"path_mappings":  []map[string]string{{"host_path": "D:\\code\\workspace\\dockgo", "container_path": "/ws-compose/dockgo"}},
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/stacks?agent="+agentRec.ID, bytes.NewReader(body))
	rr := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.handleStacks(rr, req)
	}()

	// First dispatch: stack_validate. Reply with a valid result.
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("conn.Read(validate request) error = %v", err)
	}
	var reqEnv agent.Envelope
	if err := json.Unmarshal(data, &reqEnv); err != nil {
		t.Fatalf("validate envelope unmarshal error = %v", err)
	}
	if reqEnv.Type != agent.TypeStackValidate {
		t.Fatalf("first request type = %q, want stack_validate", reqEnv.Type)
	}
	validateReply, _ := agent.NewEnvelope(agent.TypeResult, reqEnv.RequestID, agent.ResultData{
		Value: json.RawMessage(`{"valid":true,"issues":[],"warnings":[]}`),
	})
	vb, _ := validateReply.Marshal()
	if err := conn.Write(ctx, websocket.MessageText, vb); err != nil {
		t.Fatalf("conn.Write(validate result) error = %v", err)
	}

	// Second dispatch: stack_containers. The agent reports one running
	// container that matches the stack, which must bind ownership.
	_, data, err = conn.Read(ctx)
	if err != nil {
		t.Fatalf("conn.Read(containers request) error = %v", err)
	}
	var containersEnv agent.Envelope
	if err := json.Unmarshal(data, &containersEnv); err != nil {
		t.Fatalf("containers envelope unmarshal error = %v", err)
	}
	if containersEnv.Type != agent.TypeStackContainers {
		t.Fatalf("second request type = %q, want stack_containers", containersEnv.Type)
	}
	containersReply, _ := agent.NewEnvelope(agent.TypeResult, containersEnv.RequestID, agent.ResultData{
		Value: json.RawMessage(`[{"id":"cid-dockgo-agent","name":"dockgo-agent-dev","service":"dockgo-agent-dev","state":"running"}]`),
	})
	cb, _ := containersReply.Marshal()
	if err := conn.Write(ctx, websocket.MessageText, cb); err != nil {
		t.Fatalf("conn.Write(containers result) error = %v", err)
	}

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("handleStacks never returned")
	}

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rr.Code, rr.Body.String())
	}

	var resp stackDetailResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	// The stack must be bound to the matching runtime container immediately.
	if len(resp.Stack.ManagedContainers) != 1 {
		t.Fatalf("ManagedContainers = %v, want 1 (auto-bind on register)", resp.Stack.ManagedContainers)
	}
	if resp.Stack.ManagedContainers[0] != "cid-dockgo-agent" {
		t.Fatalf("ManagedContainers[0] = %q, want cid-dockgo-agent", resp.Stack.ManagedContainers[0])
	}

	// Tear down the connection and wait for the agent to go offline so the
	// async offline-state persist completes before the temp dir is removed.
	_ = conn.CloseNow()
	deadline := time.Now().Add(3 * time.Second)
	for srv.AgentManager.IsOnline(agentRec.ID) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
}

func TestAgentContainersOverlayStackOwnership(t *testing.T) {
	srv, _ := newTestServerWithAgent(t)
	mux := srv.agentTestMux()

	// Create the agent first so the stack can reference the real agent ID.
	agentRec, _, err := srv.AgentStore.Create("containers-overlay")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// A registered stack on the agent with two managed containers.
	agentStack, err := srv.StackStore.Save(stacks.Stack{
		Name:             "registry",
		ProjectName:      "registry",
		WorkingDir:       "/compose/registry",
		ComposeFiles:     []string{"/compose/registry/compose.yml"},
		PathMode:         stacks.PathModeHostNative,
		AgentID:          agentRec.ID,
		ManagedContainers: []string{"cid-registry-1", "cid-registry-2"},
	})
	if err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// A stack registered for a *different* agent that also claims
	// cid-registry-1: it must not be matched for this agent.
	if _, err := srv.StackStore.Save(stacks.Stack{
		Name:             "other-agent-registry",
		ProjectName:      "registry",
		WorkingDir:       "/compose/registry",
		ComposeFiles:     []string{"/compose/registry/compose.yml"},
		PathMode:         stacks.PathModeHostNative,
		AgentID:          "some-other-agent",
		ManagedContainers: []string{"cid-registry-1"},
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	conn, ctx := connectTestAgent(t, srv, mux, agentRec)
	if !srv.AgentManager.IsOnline(agentRec.ID) {
		t.Fatal("agent not online after handshake")
	}

	// Drive handleAgentContainers in a goroutine; it dispatches a
	// containers_list request to the connected agent.
	req := httptest.NewRequest(http.MethodGet, "/api/containers?agent="+agentRec.ID, nil)
	rr := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.handleAgentContainers(rr, req)
	}()

	// Read the dispatch request from the agent's connection and reply with a
	// container list that includes two owned containers and one unowned.
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("conn.Read(request) error = %v", err)
	}
	var reqEnv agent.Envelope
	if err := json.Unmarshal(data, &reqEnv); err != nil {
		t.Fatalf("request envelope unmarshal error = %v", err)
	}
	if reqEnv.Type != agent.TypeContainersList {
		t.Fatalf("request type = %q, want containers_list", reqEnv.Type)
	}

	reply, _ := agent.NewEnvelope(agent.TypeResult, reqEnv.RequestID, agent.ResultData{
		Value: json.RawMessage(`[
			{"id":"cid-registry-1","name":"registry","compose_project":"registry","state":"running","stack_registered":false},
			{"id":"cid-registry-2","name":"registry-ui","compose_project":"registry","state":"running","stack_registered":false},
			{"id":"cid-unowned","name":"sidecar","compose_project":"other","state":"running","stack_registered":false}
		]`),
	})
	replyBytes, _ := reply.Marshal()
	if err := conn.Write(ctx, websocket.MessageText, replyBytes); err != nil {
		t.Fatalf("conn.Write(result) error = %v", err)
	}

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("handleAgentContainers never returned")
	}

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var containers []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &containers); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if len(containers) != 3 {
		t.Fatalf("container count = %d, want 3", len(containers))
	}

	// Owned containers must be flagged as registered with the stack metadata.
	for _, c := range containers {
		switch c["id"] {
		case "cid-registry-1", "cid-registry-2":
			if c["stack_registered"] != true || c["stack_managed"] != true {
				t.Fatalf("container %v: stack_registered=%v stack_managed=%v, want true/true",
					c["id"], c["stack_registered"], c["stack_managed"])
			}
			if c["stack_id"] != agentStack.ID {
				t.Fatalf("container %v: stack_id = %v, want %v", c["id"], c["stack_id"], agentStack.ID)
			}
			if c["stack_name"] != "registry" {
				t.Fatalf("container %v: stack_name = %v, want registry", c["id"], c["stack_name"])
			}
		case "cid-unowned":
			if c["stack_registered"] == true {
				t.Fatalf("unowned container %v should remain stack_registered=false", c["id"])
			}
		}
	}

	// Tear down the connection and wait for the agent to go offline so the
	// async offline-state persist completes before the temp dir is removed
	// (avoids a Windows file-lock cleanup race in the test harness).
	_ = conn.CloseNow()
	deadline := time.Now().Add(3 * time.Second)
	for srv.AgentManager.IsOnline(agentRec.ID) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
}
