package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"dockgo/engine"
	"dockgo/logger"
	"dockgo/stacks"

	"github.com/coder/websocket"
)

var agentLog = logger.WithSubsystem("agent")

// Config configures a DockGo Agent.
type Config struct {
	ServerURL string // ws:// or wss:// endpoint (e.g. ws://host:3131/api/ws/agent)
	AgentKey  string // registration key (AGENT_KEY)
	AgentName string // optional display name; defaults to hostname
	AgentID   string // learned agent ID, persisted across reconnects

	ReconnectMin  time.Duration // initial backoff
	ReconnectMax  time.Duration // max backoff
	ReconnectMult float64       // backoff multiplier

	HeartbeatInterval time.Duration

	// StorePaths for the agent-local compose store (used only to keep the
	// engine compose helpers self-contained; remote stacks pass data in-band).
	StackStorePath string
}

// Agent is a DockGo agent client.
type Agent struct {
	cfg Config

	discovery *engine.DiscoveryEngine
	registry  *engine.RegistryClient
	store     *stacks.Store
	history   *stacks.HistoryStore

	agentID   string
	agentName string
	jwt       string

	conn   *websocket.Conn
	connMu sync.Mutex

	sendMu sync.Mutex
	stop   chan struct{}
	done   chan struct{}
}

// New constructs an Agent from environment configuration.
func New(cfg Config) (*Agent, error) {
	if strings.TrimSpace(cfg.ServerURL) == "" {
		return nil, fmt.Errorf("server URL is required")
	}
	if strings.TrimSpace(cfg.AgentKey) == "" {
		return nil, fmt.Errorf("agent key is required")
	}

	if cfg.AgentName == "" {
		hostname, err := os.Hostname()
		if err != nil || hostname == "" {
			hostname = "dockgo-agent"
		}
		cfg.AgentName = hostname
	}

	if cfg.ReconnectMin <= 0 {
		cfg.ReconnectMin = 5 * time.Second
	}
	if cfg.ReconnectMax <= 0 {
		cfg.ReconnectMax = 60 * time.Second
	}
	if cfg.ReconnectMult <= 0 {
		cfg.ReconnectMult = 2.0
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 30 * time.Second
	}
	if cfg.StackStorePath == "" {
		cfg.StackStorePath = "/app/data/agent_stacks.json"
	}

	discovery, err := engine.NewDiscoveryEngine()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize docker client: %w", err)
	}

	registry := engine.NewRegistryClient()

	store, err := stacks.NewStore(cfg.StackStorePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize stack store: %w", err)
	}
	history, err := stacks.NewHistoryStore(cfg.StackStorePath + ".history")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize stack history store: %w", err)
	}

	return &Agent{
		cfg:       cfg,
		discovery: discovery,
		registry:  registry,
		store:     store,
		history:   history,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}, nil
}

// Run connects to the server and reconnects with backoff until Stop is called.
func (a *Agent) Run(ctx context.Context) error {
	defer close(a.done)

	backoff := a.cfg.ReconnectMin

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-a.stop:
			return nil
		default:
		}

		agentLog.Info("Connecting to server",
			logger.String("url", a.cfg.ServerURL),
		)

		err := a.connect(ctx)
		if err != nil {
			agentLog.Warn("Connection failed, reconnecting",
				logger.Any("error", err),
			)
			select {
			case <-ctx.Done():
				return nil
			case <-a.stop:
				return nil
			case <-time.After(backoff):
			}

			backoff = time.Duration(float64(backoff) * a.cfg.ReconnectMult)
			if backoff > a.cfg.ReconnectMax {
				backoff = a.cfg.ReconnectMax
			}
			continue
		}

		// Connection succeeded; reset backoff for the next failure.
		backoff = a.cfg.ReconnectMin
	}
}

// Stop shuts the agent down gracefully. Safe to call multiple times.
func (a *Agent) Stop() {
	a.connMu.Lock()
	select {
	case <-a.stop:
		// Already stopping.
	default:
		close(a.stop)
	}
	a.connMu.Unlock()

	a.closeConn()
	<-a.done
}

func (a *Agent) closeConn() {
	a.connMu.Lock()
	defer a.connMu.Unlock()
	if a.conn != nil {
		_ = a.conn.Close(websocket.StatusNormalClosure, "agent stopping")
		a.conn = nil
	}
}

// connect establishes one channel and runs it until it drops.
func (a *Agent) connect(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	header := http.Header{}
	header.Set("Authorization", "Bearer "+a.cfg.AgentKey)

	conn, resp, err := websocket.Dial(ctx, a.cfg.ServerURL, &websocket.DialOptions{
		HTTPHeader: header,
	})
	if err != nil {
		if resp != nil {
			return fmt.Errorf("dial %s: %s (status %d)", a.cfg.ServerURL, err.Error(), resp.StatusCode)
		}
		return fmt.Errorf("dial %s: %w", a.cfg.ServerURL, err)
	}
	defer conn.Close(websocket.StatusInternalError, "unexpected close")

	a.connMu.Lock()
	a.conn = conn
	a.connMu.Unlock()

	defer func() {
		a.connMu.Lock()
		a.conn = nil
		a.connMu.Unlock()
	}()

	// Handshake: send register, expect welcome.
	if err := a.handshake(ctx, conn); err != nil {
		return err
	}

	// Writer goroutine (heartbeats and other periodic writes).
	writerDone := make(chan struct{})
	go a.writePump(ctx, conn, writerDone)
	defer close(writerDone)

	agentLog.Info("Agent connected",
		logger.String("agent_id", a.agentID),
		logger.String("agent_name", a.agentName),
	)

	// Read loop.
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-a.stop:
			return nil
		default:
		}

		env, err := readEnvelope(ctx, conn)
		if err != nil {
			agentLog.Warn("Channel read error",
				logger.Any("error", err),
			)
			return err
		}

		if err := a.handleEnvelope(ctx, conn, env); err != nil {
			agentLog.Warn("Envelope handling error",
				logger.Any("error", err),
			)
			return err
		}
	}
}

// handshake performs the register/welcome exchange.
func (a *Agent) handshake(ctx context.Context, conn *websocket.Conn) error {
	hostname, _ := os.Hostname()

	req := RegisterRequest{
		Hostname: hostname,
		Version:  Version,
		AgentID:  a.agentID,
		Name:     a.cfg.AgentName,
	}

	// On reconnect (we already have an agent_id), authenticate with the JWT
	// issued on the previous channel. The key is used only for the first
	// registration or if the JWT was never received.
	if a.agentID != "" && a.jwt != "" {
		req.JWT = a.jwt
	} else {
		req.Key = a.cfg.AgentKey
	}

	env, err := NewEnvelope(TypeRegister, "", req)
	if err != nil {
		return err
	}
	if err := writeEnvelope(ctx, conn, env); err != nil {
		return fmt.Errorf("failed to send register: %w", err)
	}

	reply, err := readEnvelope(ctx, conn)
	if err != nil {
		return fmt.Errorf("failed to read welcome: %w", err)
	}

	// If the JWT was rejected (e.g. key rotated, agent disabled then deleted),
	// retry once with the key so a rotated key re-registers cleanly.
	if reply.Type == TypeError && req.JWT != "" {
		req.JWT = ""
		req.Key = a.cfg.AgentKey
		a.jwt = ""

		env, err := NewEnvelope(TypeRegister, "", req)
		if err != nil {
			return err
		}
		if err := writeEnvelope(ctx, conn, env); err != nil {
			return fmt.Errorf("failed to send register: %w", err)
		}
		reply, err = readEnvelope(ctx, conn)
		if err != nil {
			return fmt.Errorf("failed to read welcome: %w", err)
		}
	}

	switch reply.Type {
	case TypeWelcome:
		var welcome WelcomeResponse
		if err := reply.Decode(&welcome); err != nil {
			return fmt.Errorf("invalid welcome payload: %w", err)
		}
		a.agentID = welcome.AgentID
		if welcome.AgentName != "" {
			a.agentName = welcome.AgentName
		} else {
			a.agentName = a.cfg.AgentName
		}
		a.jwt = welcome.JWT
		agentLog.Info("Registration accepted",
			logger.String("agent_id", a.agentID),
			logger.String("server_version", welcome.ServerVersion),
		)
		return nil
	case TypeError:
		var rd ResultData
		_ = reply.Decode(&rd)
		if rd.Error == "" {
			rd.Error = "registration rejected"
		}
		return fmt.Errorf("registration rejected: %s", rd.Error)
	default:
		return fmt.Errorf("unexpected reply during handshake: %s", reply.Type)
	}
}

// writePump sends periodic heartbeats on the channel.
func (a *Agent) writePump(ctx context.Context, conn *websocket.Conn, done chan struct{}) {
	ticker := time.NewTicker(a.cfg.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			env, _ := NewEnvelope(TypeHeartbeat, "", nil)
			if err := a.send(ctx, conn, env); err != nil {
				return
			}
		}
	}
}

// send writes an envelope under the connection send mutex.
func (a *Agent) send(ctx context.Context, conn *websocket.Conn, env Envelope) error {
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	return writeEnvelope(ctx, conn, env)
}

// handleEnvelope routes an incoming request to the op executor and sends the
// terminal result.
func (a *Agent) handleEnvelope(ctx context.Context, conn *websocket.Conn, env Envelope) error {
	switch env.Type {
	case TypePong:
		return nil
	case TypeDisconnect:
		agentLog.Info("Server requested disconnect")
		return fmt.Errorf("server requested disconnect")
	default:
	}

	if env.RequestID == "" {
		agentLog.Warn("Received request without request_id",
			logger.String("type", env.Type),
		)
		return nil
	}

	// Run each op in its own goroutine so concurrent requests are served.
	go a.runOp(ctx, conn, env)

	return nil
}

// runOp executes a single request operation and streams progress/result.
func (a *Agent) runOp(ctx context.Context, conn *websocket.Conn, env Envelope) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout(env.Type))
	defer cancel()

	switch env.Type {
	case TypeContainersList:
		a.opContainersList(ctx, conn, env)
	case TypeScan:
		a.opScan(ctx, conn, env)
	case TypeUpdate:
		a.opUpdate(ctx, conn, env)
	case TypeContainerAction:
		a.opContainerAction(ctx, conn, env)
	case TypeContainerLogs:
		a.opContainerLogs(ctx, conn, env)
	case TypeServerStats:
		a.opServerStats(ctx, conn, env)
	case TypeStackList:
		a.opStackList(ctx, conn, env)
	case TypeStackGet:
		a.opStackGet(ctx, conn, env)
	case TypeStackCreate:
		a.opStackCreate(ctx, conn, env)
	case TypeStackUpdate:
		a.opStackUpdate(ctx, conn, env)
	case TypeStackDelete:
		a.opStackDelete(ctx, conn, env)
	case TypeStackAction:
		a.opStackAction(ctx, conn, env)
	case TypeStackValidate:
		a.opStackValidate(ctx, conn, env)
	case TypeStackHistory:
		a.opStackHistory(ctx, conn, env)
	case TypeStackContainers:
		a.opStackContainers(ctx, conn, env)
	case TypeStackDiscover:
		a.opStackDiscover(ctx, conn, env)
	default:
		a.sendError(ctx, conn, env.RequestID, fmt.Errorf("unsupported operation: %s", env.Type))
	}
}

func opTimeout(msgType string) time.Duration {
	switch msgType {
	case TypeUpdate, TypeStackAction:
		return 10 * time.Minute
	case TypeScan:
		return 15 * time.Minute
	case TypeContainerLogs:
		return 10 * time.Minute
	case TypeContainersList, TypeServerStats:
		return 2 * time.Minute
	default:
		// Stack ops (validate/containers/discover) touch the daemon and the
		// agent filesystem, which can be slow on network-backed mounts.
		return 5 * time.Minute
	}
}

func (a *Agent) sendResult(ctx context.Context, conn *websocket.Conn, requestID string, value any) {
	rd := ResultData{}
	if value != nil {
		data, err := json.Marshal(value)
		if err == nil {
			rd.Value = data
		}
	}
	env, _ := NewEnvelope(TypeResult, requestID, rd)
	_ = a.send(ctx, conn, env)
}

func (a *Agent) sendError(ctx context.Context, conn *websocket.Conn, requestID string, err error) {
	rd := ResultData{Error: err.Error()}
	env, _ := NewEnvelope(TypeResult, requestID, rd)
	_ = a.send(ctx, conn, env)
}

func (a *Agent) sendProgress(ctx context.Context, conn *websocket.Conn, requestID string, pd ProgressData) {
	env, _ := NewEnvelope(TypeProgress, requestID, pd)
	_ = a.send(ctx, conn, env)
}

func readEnvelope(ctx context.Context, conn *websocket.Conn) (Envelope, error) {
	typ, data, err := conn.Read(ctx)
	if err != nil {
		return Envelope{}, err
	}
	if typ != websocket.MessageText && typ != websocket.MessageBinary {
		return Envelope{}, fmt.Errorf("unexpected websocket message type %d", typ)
	}
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return Envelope{}, fmt.Errorf("invalid agent message: %w", err)
	}
	return env, nil
}

func writeEnvelope(ctx context.Context, conn *websocket.Conn, env Envelope) error {
	data, err := env.Marshal()
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageText, data)
}

// Version is set at build time via ldflags.
var Version = "dev"

// RuntimeInfo returns agent runtime metadata.
func RuntimeInfo() map[string]string {
	return map[string]string{
		"go_version": runtime.Version(),
		"goos":       runtime.GOOS,
		"goarch":     runtime.GOARCH,
	}
}
