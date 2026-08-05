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

	"github.com/coder/websocket"
	"github.com/google/uuid"
)

// newAgentTestServer builds a Server with only the agent-related fields wired,
// so agent WebSocket + management endpoints can be tested without Docker.
func newAgentTestServer(t *testing.T) *Server {
	t.Helper()

	agentStore, err := agentstore.NewStore(filepath.Join(t.TempDir(), "agents.json"))
	if err != nil {
		t.Fatalf("agentstore.NewStore() error = %v", err)
	}

	mgr, err := agentmanager.New(agentmanager.Config{
		Store:         agentStore,
		JWTSecret:     "test-secret-for-agent-endpoints",
		JWTTTL:        time.Hour,
		MaxConcurrent: 4,
	})
	if err != nil {
		t.Fatalf("agentmanager.New() error = %v", err)
	}

	return &Server{
		AgentStore:        agentStore,
		AgentManager:      mgr,
		loginAttempts:     make(map[string]*RateLimiter),
		agentRegAttempts:  make(map[string]*RateLimiter),
	}
}

// wsTestServer serves the agent WebSocket handler and the agents CRUD handlers
// via a single ServeMux so requests can be routed without starting a listener.
func (s *Server) agentTestMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/ws/agent", s.handleAgentWebSocket)
	mux.HandleFunc("/api/agents", s.handleAgents)
	mux.HandleFunc("/api/agents/", s.handleAgentByID)
	return mux
}

func TestAgentsCRUDAndKeyRotation(t *testing.T) {
	srv := newAgentTestServer(t)
	mux := srv.agentTestMux()

	// Create an agent.
	req := httptest.NewRequest(http.MethodPost, "/api/agents", bytes.NewBufferString(`{"name":"test-host"}`))
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /api/agents status = %d, want 201: %s", rr.Code, rr.Body.String())
	}
	var created struct {
		Agent agentstore.Agent `json:"agent"`
		Key   string           `json:"key"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if created.Agent.ID == "" || !bytes.HasPrefix([]byte(created.Key), []byte("dg_")) {
		t.Fatalf("created agent = %+v key=%q", created.Agent, created.Key)
	}

	// The key must validate against the store.
	if !srv.AgentStore.CheckKey(created.Agent.ID, created.Key) {
		t.Fatal("CheckKey() = false for created agent")
	}

	// List agents.
	req = httptest.NewRequest(http.MethodGet, "/api/agents", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/agents status = %d", rr.Code)
	}
	var listed struct {
		Agents []map[string]any `json:"agents"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &listed); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if len(listed.Agents) != 1 {
		t.Fatalf("listed agents = %d, want 1", len(listed.Agents))
	}

	// Rotate the key.
	req = httptest.NewRequest(http.MethodPost, "/api/agents/"+created.Agent.ID+"/rotate-key", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("rotate-key status = %d", rr.Code)
	}
	var rotated struct {
		Agent agentstore.Agent `json:"agent"`
		Key   string           `json:"key"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &rotated); err != nil {
		t.Fatalf("Unmarshal(rotated) error = %v", err)
	}
	if srv.AgentStore.CheckKey(created.Agent.ID, created.Key) {
		t.Fatal("old key still valid after rotation")
	}
	if !srv.AgentStore.CheckKey(created.Agent.ID, rotated.Key) {
		t.Fatal("new key invalid after rotation")
	}

	// Delete the agent.
	req = httptest.NewRequest(http.MethodDelete, "/api/agents/"+created.Agent.ID, nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, want 204", rr.Code)
	}
	if _, ok := srv.AgentStore.Get(created.Agent.ID); ok {
		t.Fatal("agent still present after delete")
	}
}

func TestAgentWebSocketHandshakeAndDispatch(t *testing.T) {
	srv := newAgentTestServer(t)
	mux := srv.agentTestMux()

	agentRec, key, err := srv.AgentStore.Create("ws-host")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	server := httptest.NewServer(mux)
	defer server.Close()

	wsURL := "ws" + server.URL[len("http"):] + "/api/ws/agent"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, resp, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("websocket.Dial() error = %v (status %d)", err, resp.StatusCode)
	}
	defer conn.Close(websocket.StatusNormalClosure, "done")

	// Handshake: send register with the key.
	regEnv, _ := agent.NewEnvelope(agent.TypeRegister, "", agent.RegisterRequest{
		Key:      key,
		Hostname: "ws-host.example.com",
		Version:  "test",
		Name:     "ws-host",
	})
	regBytes, _ := regEnv.Marshal()
	if err := conn.Write(ctx, websocket.MessageText, regBytes); err != nil {
		t.Fatalf("conn.Write(register) error = %v", err)
	}

	// Read welcome.
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("conn.Read(welcome) error = %v", err)
	}
	var welcome agent.WelcomeResponse
	var welcomeEnv agent.Envelope
	if err := json.Unmarshal(data, &welcomeEnv); err != nil {
		t.Fatalf("welcome envelope unmarshal error = %v", err)
	}
	if welcomeEnv.Type != agent.TypeWelcome {
		t.Fatalf("first reply type = %q, want welcome", welcomeEnv.Type)
	}
	if err := welcomeEnv.Decode(&welcome); err != nil {
		t.Fatalf("welcome decode error = %v", err)
	}
	if welcome.AgentID != agentRec.ID {
		t.Fatalf("welcome agent_id = %q, want %q", welcome.AgentID, agentRec.ID)
	}
	if welcome.JWT == "" {
		t.Fatal("welcome did not include a JWT")
	}

	// The store should now report the agent online.
	if !srv.AgentManager.IsOnline(agentRec.ID) {
		t.Fatal("AgentManager.IsOnline() = false after handshake")
	}

	// Server dispatches a containers_list request.
	responseCh, err := srv.AgentManager.Dispatch(ctx, agentRec.ID, uuid.NewString(), agent.TypeContainersList, nil, nil)
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}

	// The agent-side (this test) receives the request envelope.
	_, data, err = conn.Read(ctx)
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

	// Reply with a result.
	reply, _ := agent.NewEnvelope(agent.TypeResult, reqEnv.RequestID, agent.ResultData{
		Value: json.RawMessage(`[{"id":"c1","name":"web","state":"running"}]`),
	})
	replyBytes, _ := reply.Marshal()
	if err := conn.Write(ctx, websocket.MessageText, replyBytes); err != nil {
		t.Fatalf("conn.Write(result) error = %v", err)
	}

	// The server's Dispatch correlation channel receives the result.
	select {
	case env := <-responseCh:
		var rd agent.ResultData
		if err := env.Decode(&rd); err != nil {
			t.Fatalf("result decode error = %v", err)
		}
		if !bytes.Contains(rd.Value, []byte(`"c1"`)) {
			t.Fatalf("result value = %s, want c1", rd.Value)
		}
	case <-ctx.Done():
		t.Fatal("server never received the dispatched result")
	}

	// Close the connection and verify the agent goes offline. Use CloseNow so
	// the underlying TCP connection is torn down immediately; the server's
	// read loop must observe the error and unregister the channel.
	_ = conn.CloseNow()

	deadline := time.Now().Add(3 * time.Second)
	for srv.AgentManager.IsOnline(agentRec.ID) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if srv.AgentManager.IsOnline(agentRec.ID) {
		t.Fatal("agent still online after connection close")
	}
}

func TestAgentWebSocketReconnectViaJWT(t *testing.T) {
	srv := newAgentTestServer(t)
	mux := srv.agentTestMux()

	agentRec, key, err := srv.AgentStore.Create("jwt-host")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	server := httptest.NewServer(mux)
	defer server.Close()

	wsURL := "ws" + server.URL[len("http"):] + "/api/ws/agent"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// First connection: register with the key, receive a JWT.
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("first dial error = %v", err)
	}
	regEnv, _ := agent.NewEnvelope(agent.TypeRegister, "", agent.RegisterRequest{
		Key:      key,
		Hostname: "jwt-host.example.com",
		Version:  "test",
		Name:     "jwt-host",
	})
	regBytes, _ := regEnv.Marshal()
	if err := conn.Write(ctx, websocket.MessageText, regBytes); err != nil {
		t.Fatalf("conn.Write(register) error = %v", err)
	}

	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("conn.Read(welcome) error = %v", err)
	}
	var welcomeEnv agent.Envelope
	if err := json.Unmarshal(data, &welcomeEnv); err != nil {
		t.Fatalf("welcome unmarshal error = %v", err)
	}
	var welcome agent.WelcomeResponse
	if err := welcomeEnv.Decode(&welcome); err != nil {
		t.Fatalf("welcome decode error = %v", err)
	}
	if welcome.JWT == "" {
		t.Fatal("welcome did not include a JWT")
	}
	_ = conn.CloseNow()

	// Second connection: reconnect using only the JWT, no key.
	conn2, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("second dial error = %v", err)
	}
	defer conn2.Close(websocket.StatusNormalClosure, "done")

	reconnEnv, _ := agent.NewEnvelope(agent.TypeRegister, "", agent.RegisterRequest{
		AgentID:  agentRec.ID,
		JWT:      welcome.JWT,
		Hostname: "jwt-host.example.com",
		Version:  "test",
	})
	reconnBytes, _ := reconnEnv.Marshal()
	if err := conn2.Write(ctx, websocket.MessageText, reconnBytes); err != nil {
		t.Fatalf("conn2.Write(register) error = %v", err)
	}

	_, data2, err := conn2.Read(ctx)
	if err != nil {
		t.Fatalf("conn2.Read(welcome) error = %v", err)
	}
	var welcomeEnv2 agent.Envelope
	if err := json.Unmarshal(data2, &welcomeEnv2); err != nil {
		t.Fatalf("second welcome unmarshal error = %v", err)
	}
	if welcomeEnv2.Type != agent.TypeWelcome {
		t.Fatalf("second reply type = %q, want welcome (got: %s)", welcomeEnv2.Type, string(data2))
	}

	if !srv.AgentManager.IsOnline(agentRec.ID) {
		t.Fatal("agent not online after JWT reconnect")
	}
}

func TestAgentWebSocketReconnectWithInvalidJWTRejects(t *testing.T) {
	srv := newAgentTestServer(t)
	mux := srv.agentTestMux()

	agentRec, key, err := srv.AgentStore.Create("bad-jwt-host")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	server := httptest.NewServer(mux)
	defer server.Close()

	wsURL := "ws" + server.URL[len("http"):] + "/api/ws/agent"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Reconnect with a tampered/invalid JWT and NO key: must be rejected.
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial error = %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "done")

	regEnv, _ := agent.NewEnvelope(agent.TypeRegister, "", agent.RegisterRequest{
		AgentID:  agentRec.ID,
		JWT:      "tampered.token.value",
		Hostname: "bad-jwt-host.example.com",
		Version:  "test",
	})
	regBytes, _ := regEnv.Marshal()
	if err := conn.Write(ctx, websocket.MessageText, regBytes); err != nil {
		t.Fatalf("conn.Write(register) error = %v", err)
	}

	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("conn.Read(reply) error = %v", err)
	}
	var replyEnv agent.Envelope
	if err := json.Unmarshal(data, &replyEnv); err != nil {
		t.Fatalf("reply unmarshal error = %v", err)
	}
	if replyEnv.Type != agent.TypeError {
		t.Fatalf("reply type = %q, want error", replyEnv.Type)
	}

	if srv.AgentManager.IsOnline(agentRec.ID) {
		t.Fatal("agent should not be online after invalid JWT")
	}
	_ = key
}
