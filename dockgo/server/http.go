package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"dockgo/api"
	"dockgo/engine"
	"dockgo/logger"
	"dockgo/notify"
	"dockgo/stacks"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var serverLog = logger.WithSubsystem("server")

//go:embed web
var content embed.FS

// Version is set at build time via ldflags.
var Version = "dev"

type Server struct {
	Port             string
	CorsOrigin       string
	APIToken         string `json:"-"`
	AuthUsername     string
	AuthPasswordHash []byte `json:"-"`
	AuthSecret       string `json:"-"`
	AllowedPaths     []string
	Discovery        *engine.DiscoveryEngine
	Registry         *engine.RegistryClient
	Notifier         *notify.AppriseNotifier
	updatesCache     map[string]bool
	cacheUnix        int64
	mu               sync.RWMutex
	lastCheckTime    time.Time
	lastCheckStat    string
	startTime        time.Time
	registryStatus   string
	registryPingTime time.Time
	loginAttempts    map[string]*RateLimiter
	loginMu          sync.Mutex
	lastDockerStatus string
	lastRegStatus    string
	revokedSessions  map[string]time.Time
	globalReauthTime time.Time
	UpdatesChan      chan string
	sessionStorePath string
	sessionMu        sync.RWMutex
	savePending      atomic.Bool
	DebugEnabled     bool
	StackStore       *stacks.Store
	StackHistory     *stacks.HistoryStore
}

type RateLimiter struct {
	count    int
	lastSeen time.Time
}

// AuthState stores persisted authentication state.
type AuthState struct {
	GlobalReauthTime int64             `json:"global_reauth_time"`
	RevokedSessions  map[string]string `json:"revoked_sessions"`
}

// NewServer creates a server instance from environment configuration.
func NewServer(port string) (*Server, error) {
	disc, err := engine.NewDiscoveryEngine()
	if err != nil {
		return nil, err
	}

	registry := engine.NewRegistryClient()

	corsOrigin := os.Getenv("CORS_ORIGIN")
	token := os.Getenv("API_TOKEN")
	authUser := os.Getenv("AUTH_USERNAME")
	authPass := os.Getenv("AUTH_PASSWORD")
	authPassHash := os.Getenv("AUTH_PASSWORD_HASH")
	authSecret := os.Getenv("AUTH_SECRET")
	costStr := os.Getenv("AUTH_BCRYPT_COST")
	sessionPath := os.Getenv("SESSION_STORE_PATH")
	stackStorePath := os.Getenv("STACK_STORE_PATH")
	stackHistoryPath := os.Getenv("STACK_HISTORY_PATH")
	allowedPathsStr := os.Getenv("ALLOWED_COMPOSE_PATHS")
	debugEnabled := os.Getenv("DOCKGO_DEBUG") == "true"

	if sessionPath == "" {
		sessionPath = "/app/data/sessions.json"
	}
	if stackStorePath == "" {
		stackStorePath = "/app/data/stacks.json"
	}
	if stackHistoryPath == "" {
		stackHistoryPath = "/app/data/stack_history.json"
	}

	if authSecret == "" {
		b := make([]byte, 32)
		if _, err := cryptorand.Read(b); err != nil {
			return nil, fmt.Errorf("failed to generate auth secret: %w", err)
		}
		authSecret = base64.RawURLEncoding.EncodeToString(b)
	}

	bcryptCost := bcrypt.DefaultCost
	if costStr != "" {
		if c, err := strconv.Atoi(costStr); err == nil && c >= bcrypt.MinCost && c <= bcrypt.MaxCost {
			bcryptCost = c
		} else {
			serverLog.Warn("Invalid AUTH_BCRYPT_COST, falling back to default",
				logger.String("provided_cost", costStr),
			)
		}
	}

	var allowedPaths []string
	if allowedPathsStr != "" {
		paths := strings.Split(allowedPathsStr, ",")
		for _, p := range paths {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				allowedPaths = append(allowedPaths, trimmed)
			}
		}
		if len(allowedPaths) > 0 {
			serverLog.Info("Security: Compose working directory restrictions enabled",
				logger.Any("paths", allowedPaths),
			)
		}
	}

	var passHash []byte
	if authUser != "" {
		if authPass == "" && authPassHash == "" {
			return nil, fmt.Errorf("authentication is enabled but no AUTH_PASSWORD or AUTH_PASSWORD_HASH provided")
		}

		if authPass != "" && authPassHash != "" {
			serverLog.Warn("Both AUTH_PASSWORD_HASH and AUTH_PASSWORD provided. Using AUTH_PASSWORD_HASH.")
			authPass = ""
		}

		if authPassHash != "" {
			passHash = []byte(authPassHash)
			_, err := bcrypt.Cost(passHash)
			if err != nil {
				return nil, fmt.Errorf("AUTH_PASSWORD_HASH provided but is not a valid bcrypt hash: %v", err)
			}
		} else if authPass != "" {
			var err error
			passHash, err = bcrypt.GenerateFromPassword([]byte(authPass), bcryptCost)
			if err != nil {
				return nil, fmt.Errorf("failed to hash password: %v", err)
			}
			authPass = ""
		}
	}

	if token == "" && authUser == "" {
		serverLog.Warn("No API_TOKEN or AUTH_USERNAME set. Updates disabled.")
	}

	serverLog.Info("Server initializing")

	stackStore, err := stacks.NewStore(stackStorePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize stack store: %w", err)
	}
	stackHistory, err := stacks.NewHistoryStore(stackHistoryPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize stack history store: %w", err)
	}

	srv := &Server{
		Port:             port,
		CorsOrigin:       corsOrigin,
		APIToken:         token,
		AuthUsername:     authUser,
		AuthPasswordHash: passHash,
		AuthSecret:       authSecret,
		AllowedPaths:     allowedPaths,
		sessionStorePath: sessionPath,
		Discovery:        disc,
		Registry:         registry,
		Notifier:         notify.NewAppriseNotifier(context.Background()),
		updatesCache:     make(map[string]bool),
		startTime:        time.Now(),
		loginAttempts:    make(map[string]*RateLimiter),
		revokedSessions:  make(map[string]time.Time),
		DebugEnabled:     debugEnabled,
		StackStore:       stackStore,
		StackHistory:     stackHistory,
	}

	srv.loadAuthState()

	return srv, nil
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/containers", s.enableCors(s.requireAuth(s.handleContainers)))
	mux.HandleFunc("/api/stream/check", s.enableCors(s.requireAuth(s.handleStreamCheck)))
	mux.HandleFunc("/api/update/", s.enableCors(s.requireAuth(s.handleUpdate)))
	mux.HandleFunc("/api/container/", s.enableCors(s.requireAuth(s.handleContainerAction)))
	mux.HandleFunc("/api/logs/", s.enableCors(s.requireAuth(s.handleContainerLogs)))
	mux.HandleFunc("/api/stacks", s.enableCors(s.requireAuth(s.handleStacks)))
	mux.HandleFunc("/api/stacks/", s.enableCors(s.requireAuth(s.handleStackByID)))

	mux.HandleFunc("/api/login", s.enableCors(s.handleLogin))
	mux.HandleFunc("/api/logout", s.enableCors(s.handleLogout))
	mux.HandleFunc("/api/logout-all", s.enableCors(s.requireAuth(s.handleLogoutAll)))
	mux.HandleFunc("/api/me", s.enableCors(s.handleMe))
	mux.HandleFunc("/api/test-notify", s.enableCors(s.requireAuth(s.handleTestNotify)))

	if s.DebugEnabled {
		serverLog.Warn("Security: Debug endpoints enabled (/api/debug/cache)")
		mux.HandleFunc("/api/debug/cache", func(w http.ResponseWriter, r *http.Request) {
			s.mu.RLock()
			defer s.mu.RUnlock()
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"cache":      s.updatesCache,
				"last_check": s.lastCheckTime,
				"stat":       s.lastCheckStat,
			})
		})
	}

	webFS, err := fs.Sub(content, "web")
	if err != nil {
		return err
	}
	mux.Handle("/", http.FileServer(http.FS(webFS)))

	logger.Info("DockGo server listening",
		logger.String("address", "localhost:"+s.Port),
	)

	go s.StartScheduler(context.Background())
	go s.cleanupRateLimiters(context.Background())

	go func() {
		if s.Notifier.WaitUntilReady(15 * time.Second) {
			s.Notifier.Notify(
				"DockGo Started",
				fmt.Sprintf("DockGo v%s is now online and listening on port %s", Version, s.Port),
				notify.TypeInfo,
			)
		} else {
			logger.Warn("Apprise: Notification server failed to become ready in time")
		}
	}()

	srv := &http.Server{
		Addr:              ":" + s.Port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	return srv.ListenAndServe()
}

func (s *Server) enableCors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.CorsOrigin == "" {
			next(w, r)
			return
		}

		origin := r.Header.Get("Origin")
		allowed := false

		if origin != "" {
			if s.CorsOrigin == "*" {
				allowed = true
			} else {
				a := strings.TrimRight(strings.ToLower(s.CorsOrigin), "/")
				b := strings.TrimRight(strings.ToLower(origin), "/")

				if a == b {
					allowed = true
				} else {
					uAlloc, err1 := url.Parse(a)
					uOrigin, err2 := url.Parse(b)
					if err1 == nil && err2 == nil {
						if uAlloc.Host != "" && uAlloc.Scheme == uOrigin.Scheme && uAlloc.Host == uOrigin.Host {
							allowed = true
						}
					}
				}
			}
		}

		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
		}

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.AuthUsername != "" {
			cookie, err := r.Cookie("dockgo_session")
			if err == nil && s.validateSessionToken(cookie.Value) {
				if r.Method != "GET" && r.Method != "OPTIONS" && r.Method != "HEAD" {
					csrfCookie, err1 := r.Cookie("dockgo_csrf")
					csrfHeader := r.Header.Get("X-CSRF-Token")
					if err1 != nil || csrfHeader == "" || csrfCookie.Value != csrfHeader {
						http.Error(w, "CSRF validation failed", http.StatusForbidden)
						return
					}
				}
				next(w, r)
				return
			}
		}

		auth := r.Header.Get("Authorization")
		token := ""
		if auth != "" && strings.HasPrefix(auth, "Bearer ") {
			token = strings.TrimPrefix(auth, "Bearer ")
		}

		if s.APIToken != "" && token != "" {
			if hmac.Equal([]byte(token), []byte(s.APIToken)) {
				serverLog.InfoContext(r.Context(), "Authentication successful via legacy API_TOKEN",
					logger.String("ip", r.RemoteAddr),
					logger.String("method", r.Method),
					logger.String("path", r.URL.Path),
				)
				next(w, r)
				return
			}
		}

		if s.APIToken == "" && s.AuthUsername == "" {
			logger.Debug("Auth failed: no auth configured")
			http.Error(w, "Updates disabled (No Auth Configured)", http.StatusForbidden)
			return
		}

		logger.Warn("Auth failed: unauthorized request")
		w.Header().Set("WWW-Authenticate", `Bearer realm="dockgo"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

func (s *Server) generateSessionToken() string {
	uuidBytes := make([]byte, 16)
	if _, err := cryptorand.Read(uuidBytes); err != nil {
		panic(fmt.Sprintf("crypto/rand failed to generate session UUID: %v", err))
	}
	uuidHex := hex.EncodeToString(uuidBytes)

	issuedAt := time.Now().Unix()
	exp := time.Now().Add(24 * time.Hour).Unix()

	data := fmt.Sprintf("%s|%s|%d|%d", uuidHex, s.AuthUsername, issuedAt, exp)
	sig := s.sign(data)
	return base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%s|%s", data, sig)))
}

func (s *Server) generateCSRFToken() string {
	b := make([]byte, 32)
	if _, err := cryptorand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed to generate CSRF token: %v", err))
	}
	return hex.EncodeToString(b)
}

func (s *Server) validateSessionToken(token string) bool {
	decodedBytes, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return false
	}
	decoded := string(decodedBytes)
	parts := strings.Split(decoded, "|")
	if len(parts) != 5 {
		return false
	}
	sessionUUID := parts[0]
	user := parts[1]
	issuedStr := parts[2]
	expStr := parts[3]
	sig := parts[4]

	if user != s.AuthUsername {
		return false
	}

	issuedAt, err := strconv.ParseInt(issuedStr, 10, 64)
	if err != nil {
		return false
	}

	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}

	s.sessionMu.RLock()
	if issuedAt < s.globalReauthTime.Unix() {
		s.sessionMu.RUnlock()
		return false
	}

	if _, exists := s.revokedSessions[sessionUUID]; exists {
		s.sessionMu.RUnlock()
		return false
	}
	s.sessionMu.RUnlock()

	expectedSig := s.sign(fmt.Sprintf("%s|%s|%s|%s", sessionUUID, user, issuedStr, expStr))
	return hmac.Equal([]byte(sig), []byte(expectedSig))
}

func (s *Server) sign(data string) string {
	h := hmac.New(sha256.New, []byte(s.AuthSecret))
	h.Write([]byte(data))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

func (s *Server) checkRateLimit(remoteAddr string) bool {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}

	s.loginMu.Lock()
	defer s.loginMu.Unlock()

	limiter, exists := s.loginAttempts[ip]
	if !exists {
		limiter = &RateLimiter{}
		s.loginAttempts[ip] = limiter
	}

	if time.Since(limiter.lastSeen) > time.Minute {
		limiter.count = 0
		limiter.lastSeen = time.Now()
	}

	limiter.count++
	limiter.lastSeen = time.Now()

	allowed := limiter.count <= 5
	if !allowed {
		serverLog.Warn("Rate limit exceeded for IP",
			logger.String("ip", ip),
			logger.Int("attempts", limiter.count),
		)
	}

	return allowed
}

func (s *Server) cleanupRateLimiters(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.loginMu.Lock()
			for ip, limiter := range s.loginAttempts {
				if time.Since(limiter.lastSeen) > 10*time.Minute {
					delete(s.loginAttempts, ip)
				}
			}
			s.loginMu.Unlock()
		}
	}
}

func (s *Server) loadAuthState() {
	if s.sessionStorePath == "" {
		return
	}

	data, err := os.ReadFile(s.sessionStorePath)
	if err != nil {
		if !os.IsNotExist(err) {
			serverLog.Error("AuthStore: Failed to read session store",
				logger.String("path", s.sessionStorePath),
				logger.Any("error", err),
			)
		}
		return
	}

	var state AuthState
	if err := json.Unmarshal(data, &state); err != nil {
		serverLog.Error("AuthStore: Corrupt JSON detected in session store",
			logger.String("path", s.sessionStorePath),
			logger.Any("error", err),
		)
		corruptPath := s.sessionStorePath + ".corrupt"
		if renameErr := os.Rename(s.sessionStorePath, corruptPath); renameErr != nil {
			serverLog.Error("AuthStore: Failed to backup corrupt store",
				logger.Any("error", renameErr),
			)
		} else {
			serverLog.Warn("AuthStore: Backed up corrupt store",
				logger.String("backup_path", corruptPath),
			)
		}
		return
	}

	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()

	if state.GlobalReauthTime > 0 {
		s.globalReauthTime = time.Unix(state.GlobalReauthTime, 0)
	}

	if state.RevokedSessions != nil {
		for id, timeStr := range state.RevokedSessions {
			if t, err := time.Parse(time.RFC3339, timeStr); err == nil {
				s.revokedSessions[id] = t
			}
		}
	}
	serverLog.Info("AuthStore: Hydrated revoked sessions from disk",
		logger.Int("count", len(s.revokedSessions)),
	)
}

func (s *Server) saveAuthState() {
	if s.sessionStorePath == "" {
		return
	}

	s.sessionMu.RLock()
	state := AuthState{
		GlobalReauthTime: s.globalReauthTime.Unix(),
		RevokedSessions:  make(map[string]string, len(s.revokedSessions)),
	}
	for id, t := range s.revokedSessions {
		state.RevokedSessions[id] = t.Format(time.RFC3339)
	}
	s.sessionMu.RUnlock()

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		serverLog.Error("AuthStore: Failed to marshal state",
			logger.Any("error", err),
		)
		return
	}

	tmpPath := s.sessionStorePath + ".tmp"
	if dir := filepath.Dir(s.sessionStorePath); dir != "" {
		_ = os.MkdirAll(dir, 0700)
	}

	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		serverLog.Error("AuthStore: Failed to write temporary state file",
			logger.String("tmp_path", tmpPath),
			logger.Any("error", err),
		)
		return
	}

	if err := os.Rename(tmpPath, s.sessionStorePath); err != nil {
		serverLog.Error("AuthStore: Failed to commit atomic auth store rename",
			logger.String("tmp_path", tmpPath),
			logger.String("target_path", s.sessionStorePath),
			logger.Any("error", err),
		)
	}
}

func (s *Server) queueSaveAuthState() {
	if s.sessionStorePath == "" {
		return
	}

	if s.savePending.CompareAndSwap(false, true) {
		go func() {
			time.Sleep(5 * time.Second)

			s.savePending.Store(false)
			s.saveAuthState()
		}()
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.AuthUsername == "" {
		http.Error(w, "User authentication not configured", http.StatusNotImplemented)
		return
	}

	if !s.checkRateLimit(r.RemoteAddr) {
		http.Error(w, "Too many login attempts", http.StatusTooManyRequests)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds struct {
		Username string `json:"username"`
		// #nosec G117 - this struct exclusively deserializes incoming login payloads, never re-serialized outward
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	defer time.Sleep(200 * time.Millisecond)

	if creds.Username != s.AuthUsername {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword(s.AuthPasswordHash, []byte(creds.Password)); err != nil {
		serverLog.WarnContext(r.Context(), "Login failed (credentials invalid)",
			logger.String("username", creds.Username),
			logger.String("ip", r.RemoteAddr),
		)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	serverLog.InfoContext(r.Context(), "Login successful",
		logger.String("username", creds.Username),
		logger.String("ip", r.RemoteAddr),
	)
	token := s.generateSessionToken()
	csrfToken := s.generateCSRFToken()

	isSecure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")

	http.SetCookie(w, &http.Cookie{
		Name:     "dockgo_session",
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "dockgo_csrf",
		Value:    csrfToken,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: false,
		Secure:   isSecure,
		SameSite: http.SameSiteStrictMode,
	})

	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("dockgo_session")
	if err == nil {
		decodedBytes, err := base64.URLEncoding.DecodeString(cookie.Value)
		if err == nil {
			parts := strings.Split(string(decodedBytes), "|")
			if len(parts) == 5 {
				sessionUUID := parts[0]
				s.sessionMu.Lock()
				s.revokedSessions[sessionUUID] = time.Now()
				s.sessionMu.Unlock()
				s.queueSaveAuthState()

				serverLog.InfoContext(r.Context(), "Session logged out",
					logger.String("ip", r.RemoteAddr),
					logger.String("session", sessionUUID[:8]),
				)
			}
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "dockgo_session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "dockgo_csrf",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: false,
		MaxAge:   -1,
	})
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *Server) handleLogoutAll(w http.ResponseWriter, r *http.Request) {
	s.sessionMu.Lock()
	s.globalReauthTime = time.Now()
	s.revokedSessions = make(map[string]time.Time)
	s.sessionMu.Unlock()

	s.queueSaveAuthState()

	http.SetCookie(w, &http.Cookie{
		Name:     "dockgo_session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "dockgo_csrf",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: false,
		MaxAge:   -1,
	})
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	loggedIn := false
	method := "none"

	if s.AuthUsername != "" {
		cookie, err := r.Cookie("dockgo_session")
		if err == nil && s.validateSessionToken(cookie.Value) {
			loggedIn = true
			method = "cookie"
		}
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"logged_in":         loggedIn,
		"auth_method":       method,
		"user_auth_enabled": s.AuthUsername != "",
		"api_token_enabled": s.APIToken != "",
	})
}

func (s *Server) handleTestNotify(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" && r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.Notifier.Notify("DockGo Test", "Test notification sent successfully.", notify.TypeSuccess)
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	_, err := s.Discovery.Client.Ping(context.Background())
	dockerStatus := "connected"
	if err != nil {
		dockerStatus = "disconnected"
	}

	uptime := time.Since(s.startTime)

	w.Header().Set("Content-Type", "application/json")

	resp := map[string]interface{}{
		"status":         "ok",
		"version":        Version,
		"docker":         dockerStatus,
		"uptime_seconds": int(uptime.Seconds()),
		"uptime_human":   formatUptime(uptime),
		"registry":       s.getRegistryStatus(),
	}

	s.mu.Lock()
	if s.lastDockerStatus != "" && s.lastDockerStatus != dockerStatus {
		if dockerStatus == "disconnected" {
			s.Notifier.Notify("DockGo Alert", "Docker Daemon disconnected!", notify.TypeFailure)
		} else {
			s.Notifier.Notify("DockGo Recovered", "Docker Daemon connected.", notify.TypeSuccess)
		}
	}
	s.lastDockerStatus = dockerStatus
	s.mu.Unlock()

	regStatus := resp["registry"].(string)
	s.mu.Lock()
	if s.lastRegStatus != "" && s.lastRegStatus != regStatus {
		if regStatus == "unreachable" {
			s.Notifier.Notify("DockGo Alert", "Registry unreachable!", notify.TypeWarning)
		} else if s.lastRegStatus == "unreachable" && regStatus == "reachable" {
			s.Notifier.Notify("DockGo Recovered", "Registry reachable.", notify.TypeSuccess)
		}
	}
	s.lastRegStatus = regStatus
	s.mu.Unlock()

	if !s.lastCheckTime.IsZero() {
		resp["last_update_check"] = s.lastCheckTime
	} else {
		resp["last_update_check"] = nil
	}

	if s.lastCheckStat != "" {
		resp["last_dockcheck_result"] = s.lastCheckStat
	} else {
		resp["last_dockcheck_result"] = "unknown"
	}

	if err != nil {
		resp["status"] = "error"
		resp["error"] = err.Error()
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	_ = json.NewEncoder(w).Encode(resp)
}

func formatUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	parts = append(parts, fmt.Sprintf("%ds", seconds))

	return strings.Join(parts, " ")
}

func (s *Server) getRegistryStatus() string {
	s.mu.RLock()
	last := s.registryPingTime
	status := s.registryStatus
	lastCheck := s.lastCheckTime
	lastStat := s.lastCheckStat
	s.mu.RUnlock()

	if lastStat == "success" && time.Since(lastCheck) < 15*time.Minute {
		return "reachable"
	}

	if time.Since(last) < 5*time.Minute && status != "" {
		return status
	}

	err := s.Registry.Ping()

	newStatus := "reachable"
	if err != nil {
		newStatus = "unreachable"
	}

	s.mu.Lock()
	s.registryPingTime = time.Now()
	s.registryStatus = newStatus
	s.mu.Unlock()

	return newStatus
}

func (s *Server) handleContainers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache")

	containers, err := s.Discovery.ListContainers(context.Background())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.mu.RLock()
	cache := s.updatesCache
	s.mu.RUnlock()

	var result []map[string]interface{}
	visibleContainers := make([]container.Summary, 0, len(containers))
	for _, c := range containers {
		name := strings.TrimPrefix(c.Names[0], "/")

		if strings.Contains(name, "_old_") {
			continue
		}
		visibleContainers = append(visibleContainers, c)

		image := c.Image
		if strings.HasPrefix(image, "sha256:") {
			if resolved, _, _, _, _, err := s.Discovery.GetContainerImageDetails(context.Background(), c.ID); err == nil && resolved != "" {
				image = resolved
			}
		}

		updateAvail := false
		if cache[c.ID] {
			updateAvail = true
		}

		var tagName string
		if idx := strings.LastIndex(image, ":"); idx > -1 && !strings.Contains(image[idx:], "/") {
			tagName = image[idx+1:]
			if idxAt := strings.LastIndex(tagName, "@"); idxAt > -1 {
				tagName = tagName[:idxAt]
			}
		} else if strings.Contains(image, "@") {
			tagName = "(digest)"
		} else {
			tagName = "latest"
		}

		result = append(result, map[string]interface{}{
			"id":                  c.ID,
			"name":                name,
			"image":               image,
			"tag":                 tagName,
			"state":               c.State,
			"status":              c.Status,
			"update_available":    updateAvail,
			"compose_project":     c.Labels["com.docker.compose.project"],
			"compose_service":     c.Labels["com.docker.compose.service"],
			"compose_working_dir": c.Labels["com.docker.compose.project.working_dir"],
			"stack_managed":       false,
			"stack_registered":    false,
			"stack_id":            "",
			"stack_name":          "",
		})
	}

	for i := range result {
		if stack, ok := s.resolveContainerStack(visibleContainers[i]); ok {
			result[i]["stack_managed"] = true
			result[i]["stack_registered"] = true
			result[i]["stack_id"] = stack.ID
			result[i]["stack_name"] = stack.Name
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func (s *Server) handleStreamCheck(w http.ResponseWriter, r *http.Request) {
	serverLog.Debug("Stream request started")
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	defer func() {
		if r := recover(); r != nil {
			serverLog.Error("PANIC in handleStreamCheck",
				logger.Any("panic", r),
			)
		}
		serverLog.Debug("Stream request ended")
	}()

	_, _ = w.Write([]byte("data: {\"type\":\"start\"}\n\n"))
	flusher.Flush()

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
	defer cancel()

	doneChan := make(chan struct{})
	var heartbeatWg sync.WaitGroup
	heartbeatWg.Add(1)

	defer heartbeatWg.Wait()
	defer close(doneChan)

	var writeMu sync.Mutex

	go func() {
		defer heartbeatWg.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-doneChan:
				return
			case <-ticker.C:
				writeMu.Lock()
				if _, err := w.Write([]byte(": ping\n\n")); err != nil {
					writeMu.Unlock()
					cancel()
					return
				}
				flusher.Flush()
				writeMu.Unlock()
			}
		}
	}()

	onProgress := func(u api.ContainerUpdate, current, total int) {
		if ctx.Err() != nil {
			return
		}

		evt := api.ProgressEvent{
			Type:            "progress",
			Current:         current,
			Total:           total,
			Container:       u.Name,
			Status:          u.Status,
			UpdateAvailable: u.UpdateAvailable,
		}
		bytes, _ := json.Marshal(evt)

		writeMu.Lock()
		defer writeMu.Unlock()

		if _, err := w.Write(append(append([]byte("data: "), bytes...), []byte("\n\n")...)); err != nil {
			serverLog.Error("Write error for container",
				logger.String("container", u.Name),
				logger.Any("error", err),
			)
			cancel()
			return
		}
		flusher.Flush()
	}

	serverLog.Debug("Starting engine scan")
	force := r.URL.Query().Get("force") == "true"
	updates, err := engine.Scan(ctx, s.Discovery, s.Registry, "", force, onProgress)
	serverLog.Debug("Engine scan completed",
		logger.Int("updates_found", len(updates)),
		logger.Any("error", err),
	)

	if ctx.Err() == nil {
		writeMu.Lock()
		defer writeMu.Unlock()

		if err != nil {
			errBytes, _ := json.Marshal(map[string]interface{}{
				"type":  "error",
				"error": err.Error(),
			})
			_, _ = w.Write([]byte("data: "))
			_, _ = w.Write(errBytes)
			_, _ = w.Write([]byte("\n\n"))
		} else {
			newCache := make(map[string]bool)
			for _, u := range updates {
				if u.UpdateAvailable {
					newCache[u.ID] = true
				}
			}

			s.mu.Lock()
			s.updatesCache = newCache
			s.lastCheckTime = time.Now()
			s.lastCheckStat = "success"
			s.mu.Unlock()

			_, _ = w.Write([]byte("data: {\"type\":\"done\", \"code\": 0}\n\n"))
		}
		flusher.Flush()
	}
}

// StartScheduler runs periodic background update scans.
func (s *Server) StartScheduler(ctx context.Context) {
	intervalStr := os.Getenv("SCAN_INTERVAL")
	if intervalStr == "" {
		intervalStr = "24h"
	}
	interval, err := time.ParseDuration(intervalStr)
	if err != nil || interval <= 0 {
		logger.Warn("Apprise: Invalid SCAN_INTERVAL, defaulting to 24h",
			logger.String("provided_interval", intervalStr),
		)
		interval = 24 * time.Hour
	}

	serverLog.Info("Starting autonomous background update scheduler",
		"interval", interval.String(),
	)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	go func() {
		time.Sleep(30 * time.Second)
		s.runScheduledScan(ctx)
	}()

	for {
		select {
		case <-ctx.Done():
			serverLog.Info("Stopping background update scheduler")
			return
		case <-ticker.C:
			s.runScheduledScan(ctx)
		}
	}
}

func (s *Server) runScheduledScan(ctx context.Context) {
	updateCtx := logger.WithUpdateID(ctx, uuid.New().String())
	serverLog.DebugContext(updateCtx, "Scheduler: Running background engine scan")
	updates, err := engine.Scan(updateCtx, s.Discovery, s.Registry, "", true, nil)
	if err != nil {
		serverLog.ErrorContext(updateCtx, "Scheduler: Engine scan failed",
			logger.Any("error", err),
		)

		s.mu.Lock()
		s.lastCheckStat = "error"
		s.mu.Unlock()
		return
	}

	newCache := make(map[string]bool)
	var newUpdates []string

	for _, u := range updates {
		if u.UpdateAvailable {
			s.mu.RLock()
			isNew := !s.updatesCache[u.ID]
			s.mu.RUnlock()

			name := strings.TrimPrefix(u.Name, "/")
			if isNew {
				if !strings.Contains(name, "_old_") {
					newUpdates = append(newUpdates, name)
				}
			}
			newCache[u.ID] = true
			serverLog.DebugContext(updateCtx, "Scheduler: Found update for container",
				logger.String("container", name),
				logger.String("container_id", u.ID),
			)
		}
	}

	if len(newUpdates) > 0 {
		title := "DockGo Update Available"
		if len(newUpdates) > 1 {
			title = "DockGo Updates Available"
		}

		var body string
		if len(newUpdates) == 1 {
			body = fmt.Sprintf("%s has an update available", newUpdates[0])
		} else {
			body = fmt.Sprintf("Updates are available for: %s", strings.Join(newUpdates, ", "))
		}

		s.Notifier.Notify(
			title,
			body,
			notify.TypeInfo,
		)
	}

	s.mu.Lock()
	s.updatesCache = newCache
	s.lastCheckTime = time.Now()
	s.lastCheckStat = "success"
	s.mu.Unlock()
}

var validContainerName = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/update/")
	serverLog.Debug("Received update request",
		logger.String("container", name),
	)

	if name == "" {
		http.Error(w, "Container name required", http.StatusBadRequest)
		return
	}

	if !validContainerName.MatchString(name) {
		http.Error(w, "Invalid container name format", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	startBytes, _ := json.Marshal(map[string]interface{}{
		"type":    "start",
		"message": fmt.Sprintf("Starting update for %s...", html.EscapeString(name)),
	})
	_, _ = w.Write([]byte("data: "))
	_, _ = w.Write(startBytes)
	_, _ = w.Write([]byte("\n\n"))
	flusher.Flush()

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	updates, err := engine.Scan(ctx, s.Discovery, s.Registry, name, false, nil)
	if err != nil || len(updates) == 0 {
		serverLog.Debug("Failed to scan container natively",
			logger.String("container", name),
			logger.Any("error", err),
		)
		if err == nil {
			err = fmt.Errorf("container not found or not running")
		}

		errBytes, _ := json.Marshal(map[string]interface{}{
			"type":  "error",
			"error": fmt.Sprintf("Failed to locate container: %v", err),
		})
		_, _ = w.Write([]byte("data: "))
		_, _ = w.Write(errBytes)
		_, _ = w.Write([]byte("\n\n"))
		flusher.Flush()
		return
	}
	targetUpdate := &updates[0]
	targetID := targetUpdate.ID

	serverLog.Debug("Resolved container name to ID",
		logger.String("container", name),
		logger.String("container_id", targetID),
	)

	// ResponseWriter writes are serialized to keep SSE frames consistent.
	var sseMu sync.Mutex
	emitSSE := func(evt api.ProgressEvent) {
		sseMu.Lock()
		defer sseMu.Unlock()
		if bytes, err := json.Marshal(evt); err == nil {
			_, _ = w.Write([]byte("data: "))
			_, _ = w.Write(bytes)
			_, _ = w.Write([]byte("\n\n"))
			flusher.Flush()
		}
	}

	opts := engine.UpdateOptions{
		Safe:            false,
		PreserveNetwork: true,
		AllowedPaths:    s.AllowedPaths,
		LogCallback:     emitSSE,
	}

	project := targetUpdate.Labels["com.docker.compose.project"]
	if project != "" {
		workingDir := targetUpdate.Labels["com.docker.compose.project.working_dir"]
		service := targetUpdate.Labels["com.docker.compose.service"]
		if stack, ok := s.StackStore.FindForComposeTarget(project, workingDir, service); ok {
			serverLog.Debug("Routing compose update through registered stack",
				logger.String("container", name),
				logger.String("project", project),
				logger.String("stack_id", stack.ID),
			)

			emitSSE(api.ProgressEvent{
				Type:      "progress",
				Status:    fmt.Sprintf("Using registered stack '%s' for project '%s'.", stack.Name, project),
				Container: name,
			})

			deployLogger := func(line string) {
				emitSSE(api.ProgressEvent{
					Type:      "progress",
					Status:    line,
					Container: name,
				})
			}

			err = s.executeStackAction(ctx, stack, "deploy", "dashboard_update", stacks.Deploy, deployLogger)
		} else {
			serverLog.Debug("No registered stack match found, using legacy compose update path",
				logger.String("container", name),
				logger.String("project", project),
			)
			err = engine.PerformUpdate(ctx, s.Discovery, targetUpdate, opts)
		}
	} else {
		serverLog.Debug("Beginning native engine update",
			logger.String("container", name),
		)
		err = engine.PerformUpdate(ctx, s.Discovery, targetUpdate, opts)
	}

	if err != nil {
		serverLog.Debug("Update process failed",
			logger.String("container", name),
			logger.Any("error", err),
		)

		errBytes, _ := json.Marshal(map[string]interface{}{
			"type":  "error",
			"error": fmt.Sprintf("Update process failed: %v", err),
		})

		sseMu.Lock()
		_, _ = w.Write([]byte("data: "))
		_, _ = w.Write(errBytes)
		_, _ = w.Write([]byte("\n\n"))
		sseMu.Unlock()
		s.Notifier.Notify(
			"DockGo Update Failed",
			fmt.Sprintf("Failed to update container %s: %v", name, err),
			notify.TypeFailure,
		)
	} else {
		s.Notifier.Notify(
			"DockGo Update Success",
			fmt.Sprintf("Container %s updated successfully", name),
			notify.TypeSuccess,
		)
		if targetID != "" {
			s.mu.Lock()
			lenBefore := len(s.updatesCache)
			delete(s.updatesCache, targetID)
			lenAfter := len(s.updatesCache)
			s.mu.Unlock()
			serverLog.Debug("Clearing cache for container",
				logger.String("container", name),
				logger.String("container_id", targetID),
				logger.Int("cache_size_before", lenBefore),
				logger.Int("cache_size_after", lenAfter),
			)
		}

		doneBytes, _ := json.Marshal(map[string]interface{}{
			"type":    "done",
			"success": true,
			"message": "Update completed successfully",
		})

		sseMu.Lock()
		_, _ = w.Write([]byte("data: "))
		_, _ = w.Write(doneBytes)
		_, _ = w.Write([]byte("\n\n"))
		sseMu.Unlock()
	}

	sseMu.Lock()
	flusher.Flush()
	sseMu.Unlock()
}

func (s *Server) handleContainerAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/container/")
	parts := strings.SplitN(path, "/", 2)

	if len(parts) != 2 || parts[1] != "action" {
		http.Error(w, "Invalid route", http.StatusNotFound)
		return
	}

	name := parts[0]
	if name == "" || !validContainerName.MatchString(name) {
		http.Error(w, "Invalid container name", http.StatusBadRequest)
		return
	}

	var reqBody struct {
		Action string `json:"action"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	action := strings.ToLower(reqBody.Action)
	if action != "start" && action != "stop" && action != "restart" {
		http.Error(w, "Invalid action. Must be 'start', 'stop', or 'restart'", http.StatusBadRequest)
		return
	}

	serverLog.Debug("Received container action request",
		logger.String("container", name),
		logger.String("action", action),
	)

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	updates, err := engine.Scan(ctx, s.Discovery, s.Registry, name, false, nil)
	if err != nil || len(updates) == 0 {
		serverLog.Debug("Native scan couldn't isolate container for action, proceeding with name",
			logger.String("container", name),
		)
	}

	var actionErr error
	switch action {
	case "start":
		actionErr = s.Discovery.StartContainer(ctx, name)
	case "stop":
		actionErr = s.Discovery.StopContainer(ctx, name)
	case "restart":
		actionErr = s.Discovery.RestartContainer(ctx, name)
	}

	if actionErr != nil {
		serverLog.Error("Container action failed",
			logger.String("container", name),
			logger.String("action", action),
			logger.Any("error", actionErr),
		)

		errBytes, _ := json.Marshal(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Failed to %s container: %v", action, actionErr),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(errBytes)

		s.Notifier.Notify(
			"DockGo Action Failed",
			fmt.Sprintf("Failed to %s container %s: %v", action, name, actionErr),
			notify.TypeFailure,
		)
		return
	}

	serverLog.Info("Container action completed successfully",
		logger.String("container", name),
		logger.String("action", action),
	)

	successBytes, _ := json.Marshal(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Successfully executed %s on %s", action, name),
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(successBytes)

	s.Notifier.Notify(
		"DockGo Container Action",
		fmt.Sprintf("Successfully executed '%s' on container %s", action, name),
		notify.TypeInfo,
	)
}

func (s *Server) handleContainerLogs(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/logs/")
	serverLog.Debug("Received logs request",
		logger.String("container", name),
	)

	if name == "" || !validContainerName.MatchString(name) {
		http.Error(w, "Invalid container name", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	updates, err := engine.Scan(ctx, s.Discovery, s.Registry, name, false, nil)
	if err != nil || len(updates) == 0 {
		serverLog.Debug("Failed to resolve container natively for logs, proceeding with name",
			logger.String("container", name),
			logger.Any("error", err),
		)
	}

	options := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Tail:       "200",
	}

	logsReader, err := s.Discovery.Client.ContainerLogs(ctx, name, options)
	if err != nil {
		serverLog.Error("Failed to fetch container logs",
			logger.String("container", name),
			logger.Any("error", err),
		)
		errBytes, _ := json.Marshal(map[string]interface{}{
			"line": fmt.Sprintf("Error fetching logs: %v", err),
		})
		_, _ = w.Write([]byte("data: "))
		_, _ = w.Write(errBytes)
		_, _ = w.Write([]byte("\n\n"))
		flusher.Flush()
		return
	}
	defer logsReader.Close()

	var sseMu sync.Mutex
	writeLine := func(line string) {
		sseMu.Lock()
		defer sseMu.Unlock()
		bytes, _ := json.Marshal(map[string]interface{}{
			"line": line,
		})
		_, _ = w.Write([]byte("data: "))
		_, _ = w.Write(bytes)
		_, _ = w.Write([]byte("\n\n"))
		flusher.Flush()
	}

	stdoutWriter := &streamWriter{cb: writeLine}
	stderrWriter := &streamWriter{cb: writeLine}

	writeLine("--- Connected to container logs ---")

	_, err = stdcopy.StdCopy(stdoutWriter, stderrWriter, logsReader)
	if err != nil && err != io.EOF && ctx.Err() == nil {
		serverLog.Error("Log stream interrupted",
			logger.String("container", name),
			logger.Any("error", err),
		)
		writeLine(fmt.Sprintf("--- Stream interrupted: %v ---", err))
	} else {
		writeLine("--- Stream disconnected ---")
	}
}

type streamWriter struct {
	cb  func(string)
	buf []byte
}

// Write buffers bytes and emits complete lines to the callback.
func (sw *streamWriter) Write(p []byte) (n int, err error) {
	sw.buf = append(sw.buf, p...)

	for {
		idx := bytes.IndexByte(sw.buf, '\n')
		if idx == -1 {
			break
		}

		line := sw.buf[:idx]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}

		sw.cb(string(line))

		sw.buf = sw.buf[idx+1:]
	}

	return len(p), nil
}
