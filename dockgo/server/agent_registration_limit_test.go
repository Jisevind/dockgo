package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"dockgo/agent"

	"github.com/coder/websocket"
)

// startAgentTestServer serves the agent handlers on a real listener and returns
// the agent WebSocket URL. Cleanup is registered with the test.
func startAgentTestServer(t *testing.T, srv *Server) string {
	t.Helper()

	server := httptest.NewServer(srv.agentTestMux())
	t.Cleanup(server.Close)

	return "ws" + server.URL[len("http"):] + "/api/ws/agent"
}

// dialAgentWS opens an agent channel at wsURL.
func dialAgentWS(t *testing.T, wsURL string) *websocket.Conn {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	conn, resp, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("websocket.Dial() error = %v (status %d)", err, resp.StatusCode)
	}
	t.Cleanup(func() { _ = conn.Close(websocket.StatusNormalClosure, "done") })

	return conn
}

// registerAgent sends a register envelope and returns the server's reply.
func registerAgent(t *testing.T, conn *websocket.Conn, req agent.RegisterRequest) agent.Envelope {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	env, err := agent.NewEnvelope(agent.TypeRegister, "", req)
	if err != nil {
		t.Fatalf("NewEnvelope() error = %v", err)
	}
	data, err := env.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatalf("conn.Write(register) error = %v", err)
	}

	_, reply, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("conn.Read(reply) error = %v", err)
	}

	var out agent.Envelope
	if err := json.Unmarshal(reply, &out); err != nil {
		t.Fatalf("Unmarshal(reply) error = %v", err)
	}
	return out
}

// failedHandshakeCount totals the failed agent handshakes recorded per IP.
func failedHandshakeCount(srv *Server) int {
	srv.loginMu.Lock()
	defer srv.loginMu.Unlock()

	total := 0
	for _, limiter := range srv.agentRegAttempts {
		total += limiter.count
	}
	return total
}

func TestStaleAgentTokenIsNotCountedAsFailedHandshake(t *testing.T) {
	srv := newAgentTestServer(t)

	agentRec, _, err := srv.AgentStore.Create("stale-token-host")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	conn := dialAgentWS(t, startAgentTestServer(t, srv))

	// A reconnecting agent presents only its channel token, and this one cannot
	// be verified: expired, or signed with a secret that has since changed.
	reply := registerAgent(t, conn, agent.RegisterRequest{
		JWT:      "not-a-verifiable-token",
		AgentID:  agentRec.ID,
		Hostname: "stale-token-host",
		Version:  "test",
		Name:     "stale-token-host",
	})

	if reply.Type != agent.TypeError {
		t.Fatalf("reply type = %q, want %q", reply.Type, agent.TypeError)
	}

	// The agent retries with its key immediately, so this must not consume the
	// per-IP budget: a fleet behind one address would otherwise lock itself out.
	if got := failedHandshakeCount(srv); got != 0 {
		t.Fatalf("failed handshake count = %d, want 0 for an unverifiable token", got)
	}
}

func TestInvalidAgentKeyIsCountedAsFailedHandshake(t *testing.T) {
	srv := newAgentTestServer(t)

	agentRec, _, err := srv.AgentStore.Create("bad-key-host")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	conn := dialAgentWS(t, startAgentTestServer(t, srv))

	reply := registerAgent(t, conn, agent.RegisterRequest{
		Key:      "dg_wrong_key",
		AgentID:  agentRec.ID,
		Hostname: "bad-key-host",
		Version:  "test",
		Name:     "bad-key-host",
	})

	if reply.Type != agent.TypeError {
		t.Fatalf("reply type = %q, want %q", reply.Type, agent.TypeError)
	}

	// A wrong key is still a credential failure and must keep counting.
	if got := failedHandshakeCount(srv); got != 1 {
		t.Fatalf("failed handshake count = %d, want 1 for a wrong key", got)
	}
}
