package agentmanager

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"dockgo/agent"
	"dockgo/agentstore"
	"dockgo/logger"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var mgrLog = logger.WithSubsystem("agentmanager")

// Conn is the minimal WebSocket surface the manager needs, so tests can
// substitute an in-memory fake.
type Conn interface {
	// Read returns the next decoded envelope from the peer.
	Read(ctx context.Context) (agent.Envelope, error)
	// Write sends an envelope to the peer. Must be safe for one concurrent writer.
	Write(ctx context.Context, env agent.Envelope) error
	// Close terminates the underlying channel.
	Close() error
}

// AgentConn tracks a single connected agent channel and its in-flight ops.
type AgentConn struct {
	agentID   string
	agentName string
	conn      Conn

	sendMu sync.Mutex

	mu        sync.Mutex
	inflight  map[string]*pendingOp
	activeOps int
	closed    bool
}

type pendingOp struct {
	response chan agent.Envelope
	progress chan agent.Envelope
}

// Manager owns the registry of connected agents and relays ops between the
// server's REST/SSE handlers and the agent channels.
type Manager struct {
	store         *agentstore.Store
	jwtSecret     []byte
	jwtTTL        time.Duration
	maxConcurrent int

	mu    sync.RWMutex
	conns map[string]*AgentConn

	// onStatusChange is invoked whenever an agent connects or disconnects.
	onStatusChange func()
}

// Config configures a Manager.
type Config struct {
	Store         *agentstore.Store
	JWTSecret     string
	JWTTTL        time.Duration
	MaxConcurrent int
	// OnStatusChange is called after any connect/disconnect event.
	OnStatusChange func()
}

// New creates a Manager.
func New(cfg Config) (*Manager, error) {
	if cfg.Store == nil {
		return nil, fmt.Errorf("agentmanager: store is required")
	}
	if strings.TrimSpace(cfg.JWTSecret) == "" {
		return nil, fmt.Errorf("agentmanager: jwt secret is required")
	}
	if cfg.JWTTTL <= 0 {
		cfg.JWTTTL = time.Hour
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 8
	}

	return &Manager{
		store:          cfg.Store,
		jwtSecret:      []byte(cfg.JWTSecret),
		jwtTTL:         cfg.JWTTTL,
		maxConcurrent:  cfg.MaxConcurrent,
		conns:          make(map[string]*AgentConn),
		onStatusChange: cfg.OnStatusChange,
	}, nil
}

// Store exposes the underlying agent store.
func (m *Manager) Store() *agentstore.Store {
	return m.store
}

// MaxConcurrentOps returns the per-agent concurrency cap.
func (m *Manager) MaxConcurrentOps() int {
	return m.maxConcurrent
}

// Claims are the JWT claims issued to agents.
type Claims struct {
	AgentID string `json:"agent_id"`
	Role    string `json:"role"`
	jwt.RegisteredClaims
}

// IssueJWT creates a short-lived token for an agent channel.
func (m *Manager) IssueJWT(agentID string) (string, error) {
	now := time.Now().UTC()
	claims := Claims{
		AgentID: agentID,
		Role:    "agent",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "dockgo",
			Subject:   agentID,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.jwtTTL)),
			ID:        uuid.NewString(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.jwtSecret)
}

// VerifyJWT validates a token and returns the agent ID.
func (m *Manager) VerifyJWT(tokenString string) (string, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.jwtSecret, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer("dockgo"), jwt.WithExpirationRequired())
	if err != nil {
		return "", err
	}
	if !token.Valid {
		return "", fmt.Errorf("invalid token")
	}
	if claims.Role != "agent" {
		return "", fmt.Errorf("token role is not agent")
	}
	return claims.AgentID, nil
}

// Register binds a channel to an agent ID. Any existing connection for the
// same agent is closed so there is exactly one live channel per agent.
func (m *Manager) Register(agentID, agentName string, conn Conn) (*AgentConn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing := m.conns[agentID]; existing != nil {
		mgrLog.Warn("Agent reconnecting, closing previous channel",
			logger.String("agent_id", agentID),
		)
		existing.Close()
	}

	ac := &AgentConn{
		agentID:   agentID,
		agentName: agentName,
		conn:      conn,
		inflight:  make(map[string]*pendingOp),
	}
	m.conns[agentID] = ac

	mgrLog.Info("Agent connected",
		logger.String("agent_id", agentID),
		logger.String("agent_name", agentName),
	)

	if m.onStatusChange != nil {
		m.onStatusChange()
	}

	return ac, nil
}

// Unregister removes a channel from the registry and fails any in-flight ops.
func (m *Manager) Unregister(agentID string, conn Conn) {
	m.mu.Lock()
	var ac *AgentConn
	if current, ok := m.conns[agentID]; ok && current.conn == conn {
		ac = current
		delete(m.conns, agentID)
	}
	m.mu.Unlock()

	if ac != nil {
		ac.failInflight(fmt.Errorf("agent connection closed"))
	}

	mgrLog.Info("Agent disconnected",
		logger.String("agent_id", agentID),
	)

	if m.onStatusChange != nil {
		m.onStatusChange()
	}
}

// IsOnline reports whether an agent has a live channel.
func (m *Manager) IsOnline(agentID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.conns[agentID] != nil
}

// OnlineIDs returns the IDs of all connected agents.
func (m *Manager) OnlineIDs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := make([]string, 0, len(m.conns))
	for id := range m.conns {
		ids = append(ids, id)
	}
	return ids
}

// AgentConn returns the channel for an agent, or nil.
func (m *Manager) AgentConn(agentID string) *AgentConn {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.conns[agentID]
}

// Dispatch sends a request to an agent and returns a channel that receives
// exactly one terminal result envelope. Progress envelopes are routed to the
// provided progress channel (which may be nil).
func (m *Manager) Dispatch(ctx context.Context, agentID, requestID, msgType string, payload any, progress chan agent.Envelope) (<-chan agent.Envelope, error) {
	ac := m.AgentConn(agentID)
	if ac == nil {
		return nil, fmt.Errorf("agent %s is offline", agentID)
	}

	env, err := agent.NewEnvelope(msgType, requestID, payload)
	if err != nil {
		return nil, err
	}

	response, err := ac.startOp(requestID, m.maxConcurrent, progress)
	if err != nil {
		return nil, err
	}

	if err := ac.send(ctx, env); err != nil {
		ac.cancelOp(requestID)
		return nil, err
	}

	return response, nil
}

// failInflight completes all pending ops with an error.
func (ac *AgentConn) failInflight(err error) {
	ac.mu.Lock()
	pending := make([]*pendingOp, 0, len(ac.inflight))
	for _, op := range ac.inflight {
		pending = append(pending, op)
	}
	ac.inflight = make(map[string]*pendingOp)
	ac.activeOps = 0
	ac.closed = true
	ac.mu.Unlock()

	for _, op := range pending {
		op.complete(agent.Envelope{
			Type: agent.TypeResult,
			Data: mustJSON(agent.ResultData{Error: err.Error()}),
		})
	}
}

func (op *pendingOp) complete(env agent.Envelope) {
	defer func() {
		_ = recover() // channel may already be closed by the reader
	}()
	select {
	case op.response <- env:
	default:
	}
}

func (ac *AgentConn) startOp(requestID string, maxConcurrent int, progress chan agent.Envelope) (<-chan agent.Envelope, error) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	if ac.closed {
		return nil, fmt.Errorf("agent connection is closed")
	}
	if ac.activeOps >= maxConcurrent {
		return nil, fmt.Errorf("agent concurrency limit (%d) reached", maxConcurrent)
	}

	op := &pendingOp{
		response: make(chan agent.Envelope, 1),
		progress: progress,
	}
	ac.inflight[requestID] = op
	ac.activeOps++

	return op.response, nil
}

// cancelOp completes an op with an error without waiting for the agent.
func (ac *AgentConn) cancelOp(requestID string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	if op, ok := ac.inflight[requestID]; ok {
		delete(ac.inflight, requestID)
		ac.activeOps--
		op.complete(agent.Envelope{
			Type: agent.TypeResult,
			Data: mustJSON(agent.ResultData{Error: "agent connection send failed"}),
		})
	}
}

// Cancel terminates an in-flight op and frees its concurrency slot. Used when
// the originating web client disconnects mid-stream.
func (ac *AgentConn) Cancel(requestID string) {
	ac.mu.Lock()
	op, ok := ac.inflight[requestID]
	if ok {
		delete(ac.inflight, requestID)
		ac.activeOps--
	}
	ac.mu.Unlock()

	if ok {
		op.complete(agent.Envelope{
			Type: agent.TypeResult,
			Data: mustJSON(agent.ResultData{Error: "operation cancelled by server"}),
		})
	}
}

// RouteMessage handles a message received from an agent, correlating it to a
// pending op by request_id.
func (ac *AgentConn) RouteMessage(env agent.Envelope) {
	ac.mu.Lock()
	op := ac.inflight[env.RequestID]
	ac.mu.Unlock()

	if op == nil {
		return
	}

	switch env.Type {
	case agent.TypeProgress:
		if op.progress != nil {
			select {
			case op.progress <- env:
			default:
				// Progress channel full: drop the event rather than block the read loop.
			}
		}
	case agent.TypeResult, agent.TypeError:
		ac.completeOp(env.RequestID, env)
	default:
		// Unknown/ignored message types.
	}
}

func (ac *AgentConn) completeOp(requestID string, env agent.Envelope) {
	ac.mu.Lock()
	op, ok := ac.inflight[requestID]
	if ok {
		delete(ac.inflight, requestID)
		ac.activeOps--
	}
	ac.mu.Unlock()

	if ok {
		op.complete(env)
	}
}

// send writes an envelope under the per-connection send mutex.
func (ac *AgentConn) send(ctx context.Context, env agent.Envelope) error {
	ac.sendMu.Lock()
	defer ac.sendMu.Unlock()

	if ac.conn == nil {
		return fmt.Errorf("agent connection is nil")
	}
	return ac.conn.Write(ctx, env)
}

// SendRaw sends an envelope directly without correlating to an op (heartbeats, etc.).
func (ac *AgentConn) SendRaw(ctx context.Context, env agent.Envelope) error {
	return ac.send(ctx, env)
}

// AgentID returns the bound agent ID.
func (ac *AgentConn) AgentID() string {
	return ac.agentID
}

// AgentName returns the bound agent display name.
func (ac *AgentConn) AgentName() string {
	return ac.agentName
}

// UnregisterConn returns the underlying channel used at registration, so the
// manager's identity check can match the same wrapper instance.
func (ac *AgentConn) UnregisterConn() Conn {
	return ac.conn
}

// IsClosed reports whether the channel has been torn down.
func (ac *AgentConn) IsClosed() bool {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	return ac.closed
}

// Close tears down the channel.
func (ac *AgentConn) Close() {
	ac.mu.Lock()
	if ac.closed {
		ac.mu.Unlock()
		return
	}
	ac.closed = true
	ac.mu.Unlock()

	if ac.conn != nil {
		_ = ac.conn.Close()
	}
	ac.failInflight(fmt.Errorf("agent connection closed"))
}

// SafeEqual is a constant-time comparison helper for API keys.
func SafeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func mustJSON(value any) json.RawMessage {
	bytes, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`{"error":"internal error"}`)
	}
	return bytes
}
