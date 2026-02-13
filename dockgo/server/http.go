package server

import (
	"bufio"
	"context"
	"dockgo/api"
	"dockgo/engine"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

//go:embed web
var content embed.FS

// Define version (could be set via ldflags)
var Version = "1.0.0"

type Server struct {
	Port             string
	APIToken         string
	Discovery        *engine.DiscoveryEngine
	updatesCache     []string
	cacheUnix        int64
	mu               sync.RWMutex
	lastCheckTime    time.Time
	lastCheckStat    string
	startTime        time.Time
	registryStatus   string
	registryPingTime time.Time
}

func NewServer(port string) (*Server, error) {
	disc, err := engine.NewDiscoveryEngine()
	if err != nil {
		return nil, err
	}

	token := os.Getenv("API_TOKEN")
	if token == "" {
		fmt.Println("⚠️  WARNING: API_TOKEN not set. Update endpoint /api/update/ is DISABLED.")
	}

	return &Server{
		Port:      port,
		APIToken:  token,
		Discovery: disc,
		startTime: time.Now(),
	}, nil
}

func (s *Server) Start() error {
	// Setup routes
	mux := http.NewServeMux()

	// API Routes
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/containers", s.enableCors(s.handleContainers))
	mux.HandleFunc("/api/stream/check", s.enableCors(s.handleStreamCheck))
	mux.HandleFunc("/api/update/", s.enableCors(s.requireAuth(s.handleUpdate)))

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

	// Static Files (Frontend)
	webFS, err := fs.Sub(content, "web")
	if err != nil {
		return err
	}
	mux.Handle("/", http.FileServer(http.FS(webFS)))

	fmt.Printf("🚀 DockGo listening at http://localhost:%s\n", s.Port)
	return http.ListenAndServe(":"+s.Port, mux)
}

// Middleware: CORS
func (s *Server) enableCors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

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
		if s.APIToken == "" {
			http.Error(w, "Update endpoint disabled (API_TOKEN not set)", http.StatusForbidden)
			return
		} else {
			auth := r.Header.Get("Authorization")
			if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			token := strings.TrimPrefix(auth, "Bearer ")
			if token != s.APIToken {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
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
	s.mu.RUnlock()

	if time.Since(last) < 5*time.Minute && status != "" {
		return status
	}

	// Ping (synchronous for now, cache makes it rare)
	reg := engine.NewRegistryClient()
	err := reg.Ping()

	newStatus := "reachable"
	if err != nil {
		// We could log details if we had a logger, e.g. fmt.Printf("Registry ping error: %v\n", err)
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

		image := c.Image
		if strings.HasPrefix(image, "sha256:") {
			if resolved, _, _, _, _, err := s.Discovery.GetContainerImageDetails(context.Background(), c.ID); err == nil && resolved != "" {
				image = resolved
			}
		}

		updateAvail := false
		for _, u := range cache {
			if u == name {
				updateAvail = true
				break
			}
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
	fmt.Println("👉 Stream Request Started")
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
			fmt.Printf("🔥 PANIC in handleStreamCheck: %v\n", r)
		}
		fmt.Println("🛑 Stream Request Ended")
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
			fmt.Printf("❌ Write Error for %s: %v\n", u.Name, err)
			cancel()
			return
		}
		flusher.Flush()
	}

	// 7. Run Scan
	registry := engine.NewRegistryClient()
	updates, err := engine.Scan(ctx, s.Discovery, registry, "", onProgress)

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
			// Update cache
			var newCache []string
			for _, u := range updates {
				if u.UpdateAvailable {
					newCache = append(newCache, u.Name)
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

// /api/update/:name
func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/update/")
	if name == "" {
		http.Error(w, "Container name required", http.StatusBadRequest)
		return
	}

	// Sanitize name a bit
	if strings.ContainsAny(name, ";&|") {
		http.Error(w, "Invalid name", http.StatusBadRequest)
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

	// Send start event
	fmt.Fprintf(w, "data: {\"type\":\"start\", \"message\": \"Starting update for %s...\"}\n\n", name)
	flusher.Flush()

	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(w, "data: {\"type\":\"error\", \"error\": \"Failed to find executable: %v\"}\n\n", err)
		return
	}

	// spawn: -y name -stream
	cmd := exec.Command(self, "-y", name, "-stream")
	cmd.Env = os.Environ()

	// Merge stderr into stdout to capture all output
	cmd.Stderr = cmd.Stdout
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(w, "data: {\"type\":\"error\", \"error\": \"Failed to pipe stdout: %v\"}\n\n", err)
		return
	}

	if err := cmd.Start(); err != nil {
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
		fmt.Fprintf(w, "data: {\"type\":\"error\", \"error\": \"Update process failed: %v\"}\n\n", err)
	} else {
		// Success
		// Invalidate cache for this container
		s.mu.Lock()
		var newC []string
		for _, c := range s.updatesCache {
			if c != name {
				newC = append(newC, c)
			}
		}
		s.updatesCache = newC
		s.mu.Unlock()

		fmt.Fprintf(w, "data: {\"type\":\"done\", \"success\": true, \"message\": \"Update completed successfully\"}\n\n")
	}
	flusher.Flush()
}
