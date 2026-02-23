package server

import (
	"bufio"
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
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

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
	CorsOrigin       string // Allowed Origin for CORS
	APIToken         string // Legacy Token
	AuthUsername     string // Optional: User Login
	AuthPasswordHash []byte // Bcrypt hash
	AuthSecret       string // For signing sessions
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
	sessionMu        sync.RWMutex
}

type RateLimiter struct {
	count    int
	lastSeen time.Time
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
	authSecret := os.Getenv("AUTH_SECRET")
	costStr := os.Getenv("AUTH_BCRYPT_COST")

	if authSecret == "" {
		// Generate random secret if not provided, restarts invalidate sessions
		authSecret = fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
	}

	bcryptCost := bcrypt.DefaultCost
	if costStr != "" {
		if c, err := strconv.Atoi(costStr); err == nil && c >= bcrypt.MinCost && c <= bcrypt.MaxCost {
			bcryptCost = c
		} else {
			logger.Warnf("Invalid AUTH_BCRYPT_COST, falling back to default")
		}
	}

	var passHash []byte
	if authUser != "" && authPass != "" {
		var err error
		passHash, err = bcrypt.GenerateFromPassword([]byte(authPass), bcryptCost)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %v", err)
		}
		// Clear plain text password from memory
		authPass = ""
	}

	if token == "" && authUser == "" {
		logger.Warnf("WARNING: No API_TOKEN or AUTH_USERNAME set. Updates disabled.")
	}

	logger.Infof("Server Initializing...")

	return &Server{
		Port:             port,
		CorsOrigin:       corsOrigin,
		APIToken:         token,
		AuthUsername:     authUser,
		AuthPasswordHash: passHash,
		AuthSecret:       authSecret,
		Discovery:        disc,
		Registry:         registry,
		Notifier:         notify.NewAppriseNotifier(context.Background()),
		updatesCache:     make(map[string]bool),
		startTime:        time.Now(),
		loginAttempts:    make(map[string]*RateLimiter),
		revokedSessions:  make(map[string]time.Time),
	}, nil
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	// API Routes
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/containers", s.enableCors(s.requireAuth(s.handleContainers)))
	mux.HandleFunc("/api/stream/check", s.enableCors(s.requireAuth(s.handleStreamCheck)))
	mux.HandleFunc("/api/update/", s.enableCors(s.requireAuth(s.handleUpdate)))

	// Auth Routes
	mux.HandleFunc("/api/login", s.enableCors(s.handleLogin))
	mux.HandleFunc("/api/logout", s.enableCors(s.handleLogout))
	mux.HandleFunc("/api/logout-all", s.enableCors(s.requireAuth(s.handleLogoutAll)))
	mux.HandleFunc("/api/me", s.enableCors(s.handleMe))
	mux.HandleFunc("/api/test-notify", s.enableCors(s.requireAuth(s.handleTestNotify)))

	// DEBUG ROUTE
	mux.HandleFunc("/api/debug/cache", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"cache":      s.updatesCache,
			"last_check": s.lastCheckTime,
			"stat":       s.lastCheckStat,
		})
	})

	webFS, err := fs.Sub(content, "web")
	if err != nil {
		return err
	}
	mux.Handle("/", http.FileServer(http.FS(webFS)))

	logger.Infof("DockGo listening at http://localhost:%s", s.Port)

	// Start background update scheduler
	go s.StartScheduler(context.Background())

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
			logger.Warnf("Apprise: Notification server failed to become ready in time.")
		}
	}()

	return http.ListenAndServe(":"+s.Port, mux)
}

// Middleware: CORS
func (s *Server) enableCors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. If CORS is not enabled/configured, do nothing (Strict Default)
		if s.CorsOrigin == "" {
			next(w, r)
			return
		}

		// 2. If Origin matches allowed origin, set headers
		origin := r.Header.Get("Origin")
		if origin == s.CorsOrigin {
			w.Header().Set("Access-Control-Allow-Origin", s.CorsOrigin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
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
			logger.Debugf("Auth Failed (No Config)")
			http.Error(w, "Updates disabled (No Auth Configured)", http.StatusForbidden)
			return
		}

		logger.Warnf("Auth Failed (Unauthorized)")
		w.Header().Set("WWW-Authenticate", `Bearer realm="dockgo"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

// Auth Helpers
func (s *Server) generateSessionToken() string {
	// Format: sessionUUID|user|issuedAt|expiration|signature
	uuidBytes := make([]byte, 16)
	cryptorand.Read(uuidBytes)
	uuidHex := hex.EncodeToString(uuidBytes)

	issuedAt := time.Now().Unix()
	exp := time.Now().Add(24 * time.Hour).Unix()

	data := fmt.Sprintf("%s|%s|%d|%d", uuidHex, s.AuthUsername, issuedAt, exp)
	sig := s.sign(data)
	return base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%s|%s", data, sig)))
}

func (s *Server) generateCSRFToken() string {
	b := make([]byte, 32)
	cryptorand.Read(b)
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
		logger.Debugf("Login Failed (redacted)")
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

	json.NewEncoder(w).Encode(map[string]bool{"success": true})
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
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *Server) handleLogoutAll(w http.ResponseWriter, r *http.Request) {
	s.sessionMu.Lock()
	s.globalReauthTime = time.Now()
	// Clear all individually revoked sessions to free memory
	s.revokedSessions = make(map[string]time.Time)
	s.sessionMu.Unlock()

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
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
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

	json.NewEncoder(w).Encode(map[string]interface{}{
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
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
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

	json.NewEncoder(w).Encode(resp)
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
	json.NewEncoder(w).Encode(result)
}

// /api/stream/check
func (s *Server) handleStreamCheck(w http.ResponseWriter, r *http.Request) {
	logger.Debugf("👉 Stream Request Started")
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
			logger.Errorf("🔥 PANIC in handleStreamCheck: %v", r)
		}
		logger.Debugf("🛑 Stream Request Ended")
	}()

	// 4. Send initial "start" event
	fmt.Fprintf(w, "data: {\"type\":\"start\"}\n\n")
	flusher.Flush()

	// Use request context for cancellation
	ctx, cancel := context.WithCancel(r.Context())
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
			logger.Errorf("❌ Write Error for %s: %v", u.Name, err)
			cancel()
			return
		}
		flusher.Flush()
	}

	// 7. Run Scan
	logger.Debugf("Starting Engine Scan...")
	force := r.URL.Query().Get("force") == "true"
	updates, err := engine.Scan(ctx, s.Discovery, s.Registry, "", force, onProgress)
	logger.Debugf("Scan returned %d updates, err=%v", len(updates), err)

	// 8. Handle result
	if ctx.Err() == nil {
		writeMu.Lock()
		defer writeMu.Unlock()

		if err != nil {
			s.mu.Lock()
			s.lastCheckStat = "error"
			s.mu.Unlock()

			fmt.Fprintf(w, "data: {\"type\":\"error\", \"error\": \"%v\"}\n\n", err)
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
		logger.Warnf("Apprise: Invalid SCAN_INTERVAL '%s', defaulting to 24h", intervalStr)
		interval = 24 * time.Hour
	}

	logger.Infof("Starting autonomous background update scheduler (interval: %v)", interval)
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
			serverLog.Infof("Stopping background update scheduler")
			return
		case <-ticker.C:
			s.runScheduledScan(ctx)
		}
	}
}

func (s *Server) runScheduledScan(ctx context.Context) {
	updateCtx := logger.WithUpdateID(ctx, uuid.New().String())
	serverLog.DebugContextf(updateCtx, "Scheduler: Running background engine scan...")
	updates, err := engine.Scan(updateCtx, s.Discovery, s.Registry, "", true, nil) // nil progress callback since this is headless
	if err != nil {
		serverLog.ErrorContextf(updateCtx, "Scheduler: Engine scan failed: %v", err)

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
			serverLog.DebugContextf(updateCtx, "Scheduler: Found update for %s (ID: %s)", name, u.ID)
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

var validContainerName = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// /api/update/:name
func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	logFile, _ := os.OpenFile("/tmp/dockgo.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if logFile != nil {
		defer logFile.Close()
	}
	debugLog := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		if logFile != nil {
			logFile.WriteString(time.Now().Format(time.RFC3339) + " " + msg + "\n")
		}
		logger.Debugf("%s", msg)
	}

	name := strings.TrimPrefix(r.URL.Path, "/api/update/")
	debugLog("Received update request for: %s", name)

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

	fmt.Fprintf(w, "data: {\"type\":\"start\", \"message\": \"Starting update for %s...\"}\n\n", name)
	flusher.Flush()

	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(w, "data: {\"type\":\"error\", \"error\": \"Failed to find executable: %v\"}\n\n", err)
		return
	}

	// Find Container ID before update (to clear cache later)
	var targetID string
	containers, _ := s.Discovery.ListContainers(context.Background())
	for _, c := range containers {
		for _, n := range c.Names {
			if strings.TrimPrefix(n, "/") == name {
				targetID = c.ID
				break
			}
		}
		if targetID != "" {
			break
		}
	}
	debugLog("Resolved container %s to ID: %s", name, targetID)

	// spawn: update -y name -stream
	cmd := exec.Command(self, "update", "-y", name, "-stream")
	cmd.Env = os.Environ()

	// Merge stderr into stdout to capture all output
	cmd.Stderr = cmd.Stdout
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		debugLog("Failed to pipe stdout: %v", err)
		fmt.Fprintf(w, "data: {\"type\":\"error\", \"error\": \"Failed to pipe stdout: %v\"}\n\n", err)
		return
	}

	if err := cmd.Start(); err != nil {
		debugLog("Failed to start update command: %v", err)
		fmt.Fprintf(w, "data: {\"type\":\"error\", \"error\": \"Failed to start update command: %v\"}\n\n", err)
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Check if line is valid JSON
		if json.Valid([]byte(line)) {
			fmt.Fprintf(w, "data: %s\n\n", line)
		} else {
			// Wrap raw text in JSON
			// Use simple string escaping or a struct
			rawEvt := api.ProgressEvent{
				Type:   "progress",
				Status: line,
			}
			if bytes, err := json.Marshal(rawEvt); err == nil {
				fmt.Fprintf(w, "data: %s\n\n", string(bytes))
			}
		}
		flusher.Flush()
	}

	if err := cmd.Wait(); err != nil {
		debugLog("Update process failed for %s: %v", name, err)
		fmt.Fprintf(w, "data: {\"type\":\"error\", \"error\": \"Update process failed: %v\"}\n\n", err)
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
			debugLog("Clearing cache for %s (ID: %s). Len Before: %d, Len After: %d", name, targetID, lenBefore, lenAfter)
		} else {
			debugLog("Could not find ID for %s, cache not cleared.", name)
		}

		fmt.Fprintf(w, "data: {\"type\":\"done\", \"success\": true, \"message\": \"Update completed successfully\"}\n\n")
	}
	flusher.Flush()
}
