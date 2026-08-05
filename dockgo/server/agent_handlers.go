package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"dockgo/agent"
	"dockgo/agentmanager"
	"dockgo/agentstore"
	"dockgo/logger"

	"github.com/coder/websocket"
)

// wsAgentReadLimit bounds the size of a single agent message (e.g. a stack
// definition pushed in-band).
const wsAgentReadLimit = 16 << 20 // 16 MiB

// handleAgentWebSocket upgrades a WebSocket connection for an agent and runs
// the channel read loop. Authentication is either a pre-shared registration
// key (first connection) or a previously issued JWT (reconnect).
func (s *Server) handleAgentWebSocket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limit failed registration attempts per IP. Healthy reconnects are
	// not throttled: the limiter only increments on a failed handshake.
	if !s.checkAgentRegistrationRate(r.RemoteAddr) {
		http.Error(w, "Too many failed registration attempts", http.StatusTooManyRequests)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		serverLog.WarnContext(r.Context(), "WebSocket upgrade failed for agent",
			logger.Any("error", err),
		)
		return
	}
	defer conn.Close(websocket.StatusInternalError, "unexpected close")
	conn.SetReadLimit(wsAgentReadLimit)

	ac, agentID, err := s.agentHandshake(r.Context(), conn)
	if err != nil {
		serverLog.WarnContext(r.Context(), "Agent handshake failed",
			logger.Any("error", err),
		)
		s.recordAgentRegistrationFailure(r.RemoteAddr)
		_ = writeAgentJSON(conn, agent.Envelope{Type: agent.TypeError, Data: marshalAgentData(agent.ResultData{Error: err.Error()})})
		return
	}

	serverLog.InfoContext(r.Context(), "Agent channel established",
		logger.String("agent_id", agentID),
		logger.String("ip", r.RemoteAddr),
	)

	// Signal the store that the agent is online and update channel metadata.
	storeAgent, ok := s.AgentStore.Get(agentID)
	if ok {
		s.AgentStore.RecordSeen(agentID, hostnameForAgent(storeAgent, agentID), "")
	}

	// The read loop runs in this goroutine; a separate writer goroutine
	// handles dispatch responses through the AgentConn send mutex.
	s.agentReadLoop(r.Context(), ac, conn, agentID)

	s.AgentStore.MarkOffline(agentID)
	s.AgentManager.Unregister(agentID, ac.UnregisterConn())
	_ = conn.Close(websocket.StatusNormalClosure, "agent disconnected")
}

// agentHandshake authenticates and registers the channel, returning the
// bound AgentConn and agent ID.
func (s *Server) agentHandshake(ctx context.Context, conn *websocket.Conn) (*agentmanager.AgentConn, string, error) {
	env, err := readAgentJSON(ctx, conn)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read registration: %w", err)
	}
	if env.Type != agent.TypeRegister {
		return nil, "", fmt.Errorf("expected register message, got %q", env.Type)
	}

	var req agent.RegisterRequest
	if err := env.Decode(&req); err != nil {
		return nil, "", fmt.Errorf("invalid register payload: %w", err)
	}

	var (
		agentID   string
		agentName string
	)

	// Preferred path: a previously issued JWT proves this is a reconnecting,
	// previously authenticated agent. This avoids the key on healthy reconnects
	// and lets key rotation take effect on the next reconnect without an outage.
	if req.JWT != "" {
		jwtAgentID, err := s.AgentManager.VerifyJWT(req.JWT)
		if err == nil && jwtAgentID != "" {
			if rec, ok := s.AgentStore.Get(jwtAgentID); ok && !rec.Disabled {
				agentID = jwtAgentID
				agentName = rec.Name
			}
		}
	}

	// Key path: agent_id + key (reconnect) or name + key (first registration).
	if agentID == "" && req.Key != "" {
		if req.AgentID != "" {
			if s.AgentStore.CheckKey(req.AgentID, req.Key) {
				agentID = req.AgentID
				if rec, ok := s.AgentStore.Get(agentID); ok {
					agentName = rec.Name
				} else {
					agentName = req.Name
				}
			}
		}

		if agentID == "" && req.Name != "" {
			if rec, ok := s.AgentStore.CheckKeyByName(req.Name, req.Key); ok {
				agentID = rec.ID
				agentName = rec.Name
			}
		}
	}

	if agentID == "" {
		return nil, "", fmt.Errorf("invalid agent credentials")
	}

	rec, ok := s.AgentStore.Get(agentID)
	if !ok {
		return nil, "", fmt.Errorf("agent record not found")
	}

	hostname := req.Hostname
	if hostname == "" {
		hostname = rec.Hostname
	}
	version := req.Version
	if version == "" {
		version = rec.Version
	}
	if _, ok := s.AgentStore.RecordSeen(agentID, hostname, version); !ok {
		return nil, "", fmt.Errorf("failed to update agent seen state")
	}

	ac, err := s.AgentManager.Register(agentID, agentName, &wsConn{conn: conn})
	if err != nil {
		return nil, "", err
	}

	jwtToken, err := s.AgentManager.IssueJWT(agentID)
	if err != nil {
		s.AgentManager.Unregister(agentID, ac.UnregisterConn())
		return nil, "", fmt.Errorf("failed to issue agent token: %w", err)
	}

	welcome := agent.WelcomeResponse{
		AgentID:       agentID,
		AgentName:     agentName,
		ServerVersion: Version,
		Capabilities: []string{
			agent.CapContainers,
			agent.CapScan,
			agent.CapUpdate,
			agent.CapLogs,
			agent.CapStats,
			agent.CapStacks,
		},
		DockerStatus: "unknown",
		JWT:          jwtToken,
		HeartbeatSec: 30,
	}

	if err := writeAgentJSON(conn, agent.Envelope{Type: agent.TypeWelcome, Data: marshalAgentData(welcome)}); err != nil {
		s.AgentManager.Unregister(agentID, ac.UnregisterConn())
		return nil, "", fmt.Errorf("failed to send welcome: %w", err)
	}

	return ac, agentID, nil
}

// agentReadLoop drains messages from the agent channel until it closes.
func (s *Server) agentReadLoop(ctx context.Context, ac *agentmanager.AgentConn, conn *websocket.Conn, agentID string) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		env, err := readAgentJSON(ctx, conn)
		if err != nil {
			serverLog.DebugContext(ctx, "Agent channel closed",
				logger.String("agent_id", agentID),
				logger.Any("error", err),
			)
			return
		}

		switch env.Type {
		case agent.TypeHeartbeat:
			_ = ac.SendRaw(ctx, agent.Envelope{Type: agent.TypePong, RequestID: env.RequestID})
		case agent.TypePong:
			// Keepalive ack; nothing to do.
		case agent.TypeWelcome, agent.TypeRegister:
			// Unexpected from the agent side; ignore.
		default:
			ac.RouteMessage(env)
		}
	}
}

// agentManageResponse is the shape returned by the agents management endpoints.
type agentManageResponse struct {
	Agent agentstore.Agent `json:"agent"`
	Key   string           `json:"key,omitempty"`
}

// handleAgents manages agent registration: list (GET) and create (POST).
func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items := s.AgentStore.List()
		online := make(map[string]bool)
		for _, id := range s.AgentManager.OnlineIDs() {
			online[id] = true
		}

		out := make([]map[string]any, 0, len(items))
		for _, agentRec := range items {
			entry := map[string]any{
				"id":         agentRec.ID,
				"name":       agentRec.Name,
				"hostname":   agentRec.Hostname,
				"version":    agentRec.Version,
				"disabled":   agentRec.Disabled,
				"last_seen":  agentRec.LastSeen,
				"created_at": agentRec.CreatedAt,
			}
			if agentRec.Disabled {
				entry["status"] = string(agentstore.StatusDisabled)
			} else if online[agentRec.ID] {
				entry["status"] = string(agentstore.StatusOnline)
			} else {
				entry["status"] = string(agentstore.StatusOffline)
			}
			out = append(out, entry)
		}

		writeJSON(w, http.StatusOK, map[string]any{"agents": out})
	case http.MethodPost:
		var payload struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		agentRec, key, err := s.AgentStore.Create(payload.Name)
		if err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}

		writeJSON(w, http.StatusCreated, agentManageResponse{Agent: agentRec, Key: key})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handleAgentByID handles agent sub-routes: disable, delete, rotate-key.
func (s *Server) handleAgentByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/agents/")
	path = strings.Trim(path, "/")
	if path == "" {
		writeError(w, http.StatusNotFound, "agent id required")
		return
	}

	parts := strings.Split(path, "/")
	agentID := parts[0]

	agentRec, ok := s.AgentStore.Get(agentID)
	if !ok {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	switch r.Method {
	case http.MethodDelete:
		// Tell a live channel to stop, then remove the record.
		if ac := s.AgentManager.AgentConn(agentID); ac != nil {
			// Best-effort graceful disconnect so the agent can re-register
			// with a fresh key instead of waiting for a socket error.
			_ = ac.SendRaw(context.Background(), agent.Envelope{Type: agent.TypeDisconnect})
			ac.Close()
		}
		if err := s.AgentStore.Delete(agentID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPost:
		if len(parts) == 2 && parts[1] == "rotate-key" {
			_, key, err := s.AgentStore.RotateKey(agentID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, agentManageResponse{Agent: agentRec, Key: key})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func hostnameForAgent(agentRec agentstore.Agent, fallback string) string {
	if agentRec.Hostname != "" {
		return agentRec.Hostname
	}
	return fallback
}

// wsConn adapts a coder/websocket Conn to the agentmanager.Conn interface.
type wsConn struct {
	conn *websocket.Conn
}

func (w *wsConn) Read(ctx context.Context) (agent.Envelope, error) {
	return readAgentJSON(ctx, w.conn)
}

func (w *wsConn) Write(ctx context.Context, env agent.Envelope) error {
	return writeAgentJSON(w.conn, env)
}

func (w *wsConn) Close() error {
	return w.conn.Close(websocket.StatusNormalClosure, "closed")
}

func readAgentJSON(ctx context.Context, conn *websocket.Conn) (agent.Envelope, error) {
	_, data, err := conn.Read(ctx)
	if err != nil {
		return agent.Envelope{}, err
	}
	var env agent.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return agent.Envelope{}, fmt.Errorf("invalid agent message: %w", err)
	}
	return env, nil
}

func writeAgentJSON(conn *websocket.Conn, env agent.Envelope) error {
	data, err := env.Marshal()
	if err != nil {
		return err
	}
	return conn.Write(context.Background(), websocket.MessageText, data)
}

func marshalAgentData(value any) json.RawMessage {
	data, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`{"error":"internal error"}`)
	}
	return data
}
