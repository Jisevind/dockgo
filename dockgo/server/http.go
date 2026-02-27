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

// Define version (injected via ldflags: -X 'dockgo/server.Version=1.0.0')
var Version = "dev"

type Server struct {
	Port             string
	CorsOrigin       string   // Allowed Origin for CORS
	APIToken         string   `json:"-"` // Legacy Token
	AuthUsername     string   // Optional: User Login
	AuthPasswordHash []byte   `json:"-"` // Bcrypt hash
	AuthSecret       string   `json:"-"` // For signing sessions
	AllowedPaths     []string // Allowed base paths for Compose working directories
	Discovery        *engine.DiscoveryEngine
	Registry         *engine.RegistryClient
	Notifier         *notify.AppriseNotifier
	updatesCache     map[string]bool // key: Container ID
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
	UpdatesChan      chan string // Added UpdatesChan
	sessionStorePath string      // Added sessionStorePath
	sessionMu        sync.RWMutex
	savePending      atomic.Bool // Debounce session persistence writes
	DebugEnabled     bool        // Enable debug endpoints
}

type RateLimiter struct {
	count    int
	lastSeen time.Time
}

// AuthState is used to serialize and deserialize the session persistence store
type AuthState struct {
	GlobalReauthTime int64             `json:"global_reauth_time"`
	RevokedSessions  map[string]string `json:"revoked_sessions"` // map[UUID]RFC3339
}

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
	allowedPathsStr := os.Getenv("ALLOWED_COMPOSE_PATHS")
	debugEnabled := os.Getenv("DOCKGO_DEBUG") == "true"

	if sessionPath == "" {
		sessionPath = "/app/data/sessions.json"
	}

	if authSecret == "" {
		// Generate random secret if not provided, restarts invalidate sessions
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

	// Parse allowed Compose paths (comma-separated list)
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
			// Let it go out of scope ASAP since hash takes precedence
			authPass = ""
		}

		if authPassHash != "" {
			passHash = []byte(authPassHash)
			// Validate that it's actually a valid bcrypt hash
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
			// Clear plain text password from memory
			authPass = ""
		}
	}

	if token == "" && authUser == "" {
		serverLog.Warn("No API_TOKEN or AUTH_USERNAME set. Updates disabled.")
	}

	serverLog.Info("Server initializing")

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
	}

	srv.loadAuthState()

	return srv, nil
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	// API Routes
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/containers", s.enableCors(s.requireAuth(s.handleContainers)))
	mux.HandleFunc("/api/stream/check", s.enableCors(s.requireAuth(s.handleStreamCheck)))
	mux.HandleFunc("/api/update/", s.enableCors(s.requireAuth(s.handleUpdate)))
	mux.HandleFunc("/api/container/", s.enableCors(s.requireAuth(s.handleContainerAction)))
	mux.HandleFunc("/api/logs/", s.enableCors(s.requireAuth(s.handleContainerLogs)))

	// Auth Routes
	mux.HandleFunc("/api/login", s.enableCors(s.handleLogin))
	mux.HandleFunc("/api/logout", s.enableCors(s.handleLogout))
	mux.HandleFunc("/api/logout-all", s.enableCors(s.requireAuth(s.handleLogoutAll)))
	mux.HandleFunc("/api/me", s.enableCors(s.handleMe))
	mux.HandleFunc("/api/test-notify", s.enableCors(s.requireAuth(s.handleTestNotify)))

	// DEBUG ROUTE
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

	// Start background update scheduler
	go s.StartScheduler(context.Background())
	go s.cleanupRateLimiters(context.Background())

	// Send startup notification in a goroutine so it doesn't block the server
	go func() {
		// Give Apprise up to 15 seconds to wake up
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
		// Explicitly omitting WriteTimeout because the application utilizes
		// long-running Server-Sent Events (SSE) for its /api/containers stream,
		// and WriteTimeout rigidly limits the maximum duration of the entire connection.
	}

	return srv.ListenAndServe()
}

// Middleware: CORS
func (s *Server) enableCors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. If CORS is not enabled/configured, do nothing (Strict Default)
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
				// Clean slashes and case
				a := strings.TrimRight(strings.ToLower(s.CorsOrigin), "/")
				b := strings.TrimRight(strings.ToLower(origin), "/")

				if a == b {
					allowed = true
				} else {
					// Fallback to hostname comparison using net/url
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

		// 2. If Origin matches loosely, set headers using the exact request origin
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
		}

		// 3. Handle Preflight OPTIONS
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

// Middleware: Auth
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Check Session Cookie (User Login) - PRIORITIZE
		if s.AuthUsername != "" {
			cookie, err := r.Cookie("dockgo_session")
			if err == nil && s.validateSessionToken(cookie.Value) {
				// CSRF Protection for state-changing methods
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

		// 2. Check Legacy Token, Header Only
		auth := r.Header.Get("Authorization")
		token := ""
		if auth != "" && strings.HasPrefix(auth, "Bearer ") {
			token = strings.TrimPrefix(auth, "Bearer ")
		}

		if s.APIToken != "" && token != "" {
			// Use Constant-Time Comparison to prevent timing attacks
			if hmac.Equal([]byte(token), []byte(s.APIToken)) {
				next(w, r)
				return
			}
		}

		// 3. Fallback: Fail
		// If neither configured, fail.
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

// generateSessionToken produces a secure, random UUID for session identification.
func (s *Server) generateSessionToken() string {
	// Format: sessionUUID|user|issuedAt|expiration|signature
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

// validateSessionToken verifies if a token is cryptographically valid, not revoked,
// and correctly signed by the server's secret.
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

	// 1. Global Revocation Check
	s.sessionMu.RLock()
	if issuedAt < s.globalReauthTime.Unix() {
		s.sessionMu.RUnlock()
		return false
	}

	// 2. Individual Revocation Check
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

// Rate Limiting
func (s *Server) checkRateLimit(remoteAddr string) bool {
	// IP parsing
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// Fallback if no port or other format issue
		ip = remoteAddr
	}

	s.loginMu.Lock()
	defer s.loginMu.Unlock()

	limiter, exists := s.loginAttempts[ip]
	if !exists {
		limiter = &RateLimiter{}
		s.loginAttempts[ip] = limiter
	}

	// Reset if more than 1 minute passed
	if time.Since(limiter.lastSeen) > time.Minute {
		limiter.count = 0
		limiter.lastSeen = time.Now()
	}

	limiter.count++
	limiter.lastSeen = time.Now()

	// Max 5 attempts per minute
	return limiter.count <= 5
}

// cleanupRateLimiters periodically prunes stale IP tracking data to prevent OOMs
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

// loadAuthState hydrates session revocations from the JSON persistence layer.
// Handles missing files gracefully and detects/recovers uniformly from corruption.
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
		return // Start fresh
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
		return // Start fresh
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

// saveAuthState safely commits session invariants to disk without holding hot locks during I/O.
// Uses an atomic .tmp file swap structure to prevent corruption on crash.
func (s *Server) saveAuthState() {
	if s.sessionStorePath == "" {
		return
	}

	s.sessionMu.RLock()
	// State copy
	state := AuthState{
		GlobalReauthTime: s.globalReauthTime.Unix(),
		RevokedSessions:  make(map[string]string, len(s.revokedSessions)),
	}
	for id, t := range s.revokedSessions {
		state.RevokedSessions[id] = t.Format(time.RFC3339)
	}
	s.sessionMu.RUnlock() // Complete lock before doing expensive marshal and IO

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		serverLog.Error("AuthStore: Failed to marshal state",
			logger.Any("error", err),
		)
		return
	}

	tmpPath := s.sessionStorePath + ".tmp"
	// Ensure directory exists
	if dir := filepath.Dir(s.sessionStorePath); dir != "" {
		_ = os.MkdirAll(dir, 0700)
	}

	// Write to tmp safely using 0600
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		serverLog.Error("AuthStore: Failed to write temporary state file",
			logger.String("tmp_path", tmpPath),
			logger.Any("error", err),
		)
		return
	}

	// Atomic commit
	if err := os.Rename(tmpPath, s.sessionStorePath); err != nil {
		serverLog.Error("AuthStore: Failed to commit atomic auth store rename",
			logger.String("tmp_path", tmpPath),
			logger.String("target_path", s.sessionStorePath),
			logger.Any("error", err),
		)
	}
}

// queueSaveAuthState debounces disk writes for high-frequency session revocations (storms)
func (s *Server) queueSaveAuthState() {
	if s.sessionStorePath == "" {
		return
	}

	// Only trigger background save if one isn't already sleeping/pending
	if s.savePending.CompareAndSwap(false, true) {
		go func() {
			// Debounce window
			time.Sleep(5 * time.Second)

			// Unset flag immediately before writing.
			// Any rapid events that happen *during* the disk I/O will correctly queue a fresh save.
			s.savePending.Store(false)
			s.saveAuthState()
		}()
	}
}

// Auth Handlers
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.AuthUsername == "" {
		http.Error(w, "User authentication not configured", http.StatusNotImplemented)
		return
	}

	if !s.checkRateLimit(r.RemoteAddr) {
		// 429 Too Many Requests
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

	// Slow down response slightly to prevent timing attacks
	defer time.Sleep(200 * time.Millisecond)

	if creds.Username != s.AuthUsername {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Verify Password Hash
	if err := bcrypt.CompareHashAndPassword(s.AuthPasswordHash, []byte(creds.Password)); err != nil {
		serverLog.Debug("Login failed (credentials redacted)")
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Success
	token := s.generateSessionToken()
	csrfToken := s.generateCSRFToken()

	// Determine if Secure flag should be set
	isSecure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")

	http.SetCookie(w, &http.Cookie{
		Name:     "dockgo_session",
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   isSecure, // Strict secure flag
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "dockgo_csrf",
		Value:    csrfToken,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: false, // Must be accessible to JS
		Secure:   isSecure,
		SameSite: http.SameSiteStrictMode,
	})

	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Revoke the session UUID
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
	// Clear all individually revoked sessions to free memory
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

	// Check Cookie
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

// /api/health
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Ping Docker
	_, err := s.Discovery.Client.Ping(context.Background())
	dockerStatus := "connected"
	if err != nil {
		dockerStatus = "disconnected"
	}

	uptime := time.Since(s.startTime)

	w.Header().Set("Content-Type", "application/json")

	// Create map for response to handle optional fields cleanly
	resp := map[string]interface{}{
		"status":         "ok",
		"version":        Version,
		"docker":         dockerStatus,
		"uptime_seconds": int(uptime.Seconds()),
		"uptime_human":   formatUptime(uptime),
		"registry":       s.getRegistryStatus(),
	}

	// Notify on state change (Docker)
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

	// Notify on state change (Registry)
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

	// Use recent successful scan as proof of connectivity
	if lastStat == "success" && time.Since(lastCheck) < 15*time.Minute {
		return "reachable"
	}

	if time.Since(last) < 5*time.Minute && status != "" {
		return status
	}

	// Ping (synchronous fallback)
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

// /api/containers
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
	for _, c := range containers {
		name := strings.TrimPrefix(c.Names[0], "/")

		// Hide temporary update containers from the UI
		if strings.Contains(name, "_old_") {
			continue
		}

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

		// Parse Image:Tag
		var tagName string
		if idx := strings.LastIndex(image, ":"); idx > -1 && !strings.Contains(image[idx:], "/") {
			tagName = image[idx+1:]
			// If it's a digest (e.g. some-image@sha256:...), the tag might be implicit or mapped.
			// If it's "ubuntu:latest", tag is "latest".
			// If it's "ubuntu:latest@sha256:...", tag is "latest".
			// If it's "ubuntu@sha256:...", tag is empty/unknown.
			if idxAt := strings.LastIndex(tagName, "@"); idxAt > -1 {
				tagName = tagName[:idxAt]
			}
		} else if strings.Contains(image, "@") {
			// Digest only, no tag
			tagName = "(digest)"
		} else {
			tagName = "latest" // Assume latest if no tag? Or unknown? Docker defaults to latest.
		}

		result = append(result, map[string]interface{}{
			"id":               c.ID,
			"name":             name,
			"image":            image,
			"tag":              tagName,
			"state":            c.State,
			"status":           c.Status,
			"update_available": updateAvail,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// /api/stream/check
func (s *Server) handleStreamCheck(w http.ResponseWriter, r *http.Request) {
	serverLog.Debug("Stream request started")
	// 1. Set headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no") // Disable Nginx buffering

	// 2. Check flusher
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// 3. Panic recovery
	defer func() {
		if r := recover(); r != nil {
			serverLog.Error("PANIC in handleStreamCheck",
				logger.Any("panic", r),
			)
		}
		serverLog.Debug("Stream request ended")
	}()

	// 4. Send initial "start" event
	fmt.Fprintf(w, "data: {\"type\":\"start\"}\n\n")
	flusher.Flush()

	// Use request context with timeout for cancellation
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
	defer cancel()

	// 5. Heartbeat logic
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
				if _, err := fmt.Fprintf(w, ": ping\n\n"); err != nil {
					writeMu.Unlock()
					cancel()
					return
				}
				flusher.Flush()
				writeMu.Unlock()
			}
		}
	}()

	// 6. Callback for progress
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

		if _, err := fmt.Fprintf(w, "data: %s\n\n", string(bytes)); err != nil {
			serverLog.Error("Write error for container",
				logger.String("container", u.Name),
				logger.Any("error", err),
			)
			cancel()
			return
		}
		flusher.Flush()
	}

	// 7. Run Scan
	serverLog.Debug("Starting engine scan")
	force := r.URL.Query().Get("force") == "true"
	updates, err := engine.Scan(ctx, s.Discovery, s.Registry, "", force, onProgress)
	serverLog.Debug("Engine scan completed",
		logger.Int("updates_found", len(updates)),
		logger.Any("error", err),
	)

	// 8. Handle result
	if ctx.Err() == nil {
		writeMu.Lock()
		defer writeMu.Unlock()

		if err != nil {
			// Safely marshal the error object
			errBytes, _ := json.Marshal(map[string]interface{}{
				"type":  "error",
				"error": err.Error(),
			})
			fmt.Fprintf(w, "data: %s\n\n", string(errBytes))
		} else {
			// Update the cache explicitly so the UI's subsequent fetch to /api/containers sees it.
			// However, explicitly do NOT fire a notification. The background scheduler handles that.
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

			fmt.Fprintf(w, "data: {\"type\":\"done\", \"code\": 0}\n\n")
		}
		flusher.Flush()
	}
}

// StartScheduler is an autonomous background daemon that polls the Docker registries
// on a set interval and issues Apprise notifications. It acts as the single source of truth
// for update alerts, cleanly decoupled from the UI.
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

	logger.Info("Starting autonomous background update scheduler",
		logger.String("interval", interval.String()),
	)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Optionally do an immediate invisible scan on startup (after a slight delay so Docker API is ready)
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
	updates, err := engine.Scan(updateCtx, s.Discovery, s.Registry, "", true, nil) // nil progress callback since this is headless
	if err != nil {
		serverLog.ErrorContext(updateCtx, "Scheduler: Engine scan failed",
			logger.Any("error", err),
		)

		s.mu.Lock()
		s.lastCheckStat = "error"
		s.mu.Unlock()
		return
	}

	// Update cache
	newCache := make(map[string]bool)
	var newUpdates []string

	for _, u := range updates {
		if u.UpdateAvailable {
			// Ensure we check the map thread-safely
			s.mu.RLock()
			isNew := !s.updatesCache[u.ID]
			s.mu.RUnlock()

			name := strings.TrimPrefix(u.Name, "/")
			if isNew {
				// Hide temporary update containers from the UI and Alerts
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

// /api/update/:name
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
	fmt.Fprintf(w, "data: %s\n\n", string(startBytes))
	flusher.Flush()

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	// 1. Scan the specific container natively
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
		fmt.Fprintf(w, "data: %s\n\n", string(errBytes))
		flusher.Flush()
		return
	}
	targetUpdate := &updates[0]
	targetID := targetUpdate.ID

	serverLog.Debug("Resolved container name to ID",
		logger.String("container", name),
		logger.String("container_id", targetID),
	)

	// 2. Wrap SSE Writes inside a local lock
	// The HTTP ResponseWriter is inherently NOT thread-safe for concurrent SSE pushes when flushed.
	var sseMu sync.Mutex
	emitSSE := func(evt api.ProgressEvent) {
		sseMu.Lock()
		defer sseMu.Unlock()
		if bytes, err := json.Marshal(evt); err == nil {
			fmt.Fprintf(w, "data: %s\n\n", string(bytes))
			flusher.Flush()
		}
	}

	// 3. Delegate to native engine update
	opts := engine.UpdateOptions{
		Safe:            false, // GUI updates are explicit commands (typically bypassing safe mode limits unless instructed otherwise)
		PreserveNetwork: true,
		AllowedPaths:    s.AllowedPaths,
		LogCallback:     emitSSE,
	}

	serverLog.Debug("Beginning native engine update",
		logger.String("container", name),
	)
	err = engine.PerformUpdate(ctx, s.Discovery, targetUpdate, opts)

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
		fmt.Fprintf(w, "data: %s\n\n", string(errBytes))
		sseMu.Unlock()
		s.Notifier.Notify(
			"DockGo Update Failed",
			fmt.Sprintf("Failed to update container %s: %v", name, err),
			notify.TypeFailure,
		)
	} else {
		// Success
		s.Notifier.Notify(
			"DockGo Update Success",
			fmt.Sprintf("Container %s updated successfully", name),
			notify.TypeSuccess,
		)
		// Invalidate cache ONLY for this container
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
		fmt.Fprintf(w, "data: %s\n\n", string(doneBytes))
		sseMu.Unlock()
	}

	sseMu.Lock()
	flusher.Flush()
	sseMu.Unlock()
}

// /api/container/:name/action
func (s *Server) handleContainerAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract everything after /api/container/
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

	// 1. Resolve container name to ID natively to ensure it exists
	// We use Scan just to find the container ID, we don't care about updates here.
	updates, err := engine.Scan(ctx, s.Discovery, s.Registry, name, false, nil)
	if err != nil || len(updates) == 0 {
		// If native scan fails to find it by name, we might be dealing with a compose container.
		// For safety, let's just use the name directly against the Docker client.
		// The Docker API accepts names for start/stop/restart anyway.
		serverLog.Debug("Native scan couldn't isolate container for action, proceeding with name",
			logger.String("container", name),
		)
	}

	// 2. Perform action
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

	// 3. Success
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

	// Send notification (Title Case the action)
	s.Notifier.Notify(
		"DockGo Container Action",
		fmt.Sprintf("Successfully executed '%s' on container %s", action, name),
		notify.TypeInfo,
	)
}

// /api/logs/:name
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

	// 10 minute timeout for streaming logs
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	// 1. Resolve to ID (just to be safe that it's a real container)
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

	// 2. Call Docker SDK
	logsReader, err := s.Discovery.Client.ContainerLogs(ctx, name, options)
	if err != nil {
		serverLog.Error("Failed to fetch container logs",
			logger.String("container", name),
			logger.Any("error", err),
		)
		errBytes, _ := json.Marshal(map[string]interface{}{
			"line": fmt.Sprintf("Error fetching logs: %v", err),
		})
		fmt.Fprintf(w, "data: %s\n\n", string(errBytes))
		flusher.Flush()
		return
	}
	defer logsReader.Close()

	// 3. Setup stdcopy pipes
	var sseMu sync.Mutex
	writeLine := func(line string) {
		sseMu.Lock()
		defer sseMu.Unlock()
		bytes, _ := json.Marshal(map[string]interface{}{
			"line": line,
		})
		fmt.Fprintf(w, "data: %s\n\n", string(bytes))
		flusher.Flush()
	}

	// Docker logs are multiplexed. stdcopy splits them cleanly.
	// We'll pipe both stdout and stderr to our writeLine func via custom io.Writers
	stdoutWriter := &streamWriter{cb: writeLine}
	stderrWriter := &streamWriter{cb: writeLine}

	// Write initial connection line
	writeLine("--- Connected to container logs ---")

	// Start demultiplexing
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

// streamWriter allows us to capture stdcopy output line-by-line
type streamWriter struct {
	cb  func(string)
	buf []byte
}

func (sw *streamWriter) Write(p []byte) (n int, err error) {
	// Combine with any previously buffered bytes
	sw.buf = append(sw.buf, p...)

	// Process all complete lines
	for {
		idx := bytes.IndexByte(sw.buf, '\n')
		if idx == -1 {
			// No complete line yet, wait for more data
			break
		}

		// Extract line (without newline)
		line := sw.buf[:idx]
		// Handle \r\n
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}

		sw.cb(string(line))

		// Advance buffer past the newline
		sw.buf = sw.buf[idx+1:]
	}

	return len(p), nil
}
