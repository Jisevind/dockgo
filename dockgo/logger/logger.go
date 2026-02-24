package logger

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

type loggerContextKey string

const (
	UpdateIDKey loggerContextKey = "updateID"
)

var (
	currentLevel = new(slog.LevelVar)
	globalLogger *slog.Logger
	mu           sync.RWMutex
)

func init() {
	currentLevel.Set(slog.LevelInfo)
	setupLogger()
}

func setupLogger() {
	opts := &slog.HandlerOptions{
		Level: currentLevel,
	}

	var handler slog.Handler
	logFormat := strings.ToLower(os.Getenv("LOG_FORMAT"))

	// Default to JSON in Docker containers, or if explicitly set to "json"
	if logFormat == "json" || (logFormat == "" && isRunningInDocker()) {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	globalLogger = slog.New(handler)
	slog.SetDefault(globalLogger)
}

// isRunningInDocker checks if we're running inside a Docker container
func isRunningInDocker() bool {
	// Check for .dockerenv file (standard for containers)
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	// Check for Docker in cgroup (another common method)
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		return strings.Contains(string(data), "docker") || strings.Contains(string(data), "containerd")
	}
	return false
}

// SetLevel dynamically adjusts the global logging level
func SetLevel(levelStr string) {
	switch strings.ToLower(levelStr) {
	case "debug":
		currentLevel.Set(slog.LevelDebug)
	case "info":
		currentLevel.Set(slog.LevelInfo)
	case "warn":
		currentLevel.Set(slog.LevelWarn)
	case "error":
		currentLevel.Set(slog.LevelError)
	default:
		currentLevel.Set(slog.LevelInfo)
	}
}

// SubsystemLogger wraps slog.Logger to provide structured logging methods
type SubsystemLogger struct {
	sl *slog.Logger
}

// Structured logging methods - PREFERRED for new code
// These methods pass structured attributes directly to slog for machine-readable logs
// Example: scannerLog.Info("scan completed", logger.Int("containers", 42))
func (s *SubsystemLogger) Info(msg string, args ...any) {
	s.sl.Info(msg, args...)
}

func (s *SubsystemLogger) Debug(msg string, args ...any) {
	s.sl.Debug(msg, args...)
}

func (s *SubsystemLogger) Warn(msg string, args ...any) {
	s.sl.Warn(msg, args...)
}

func (s *SubsystemLogger) Error(msg string, args ...any) {
	s.sl.Error(msg, args...)
}

// Structured logging with context - preferred for new code
func (s *SubsystemLogger) InfoContext(ctx context.Context, msg string, args ...any) {
	s.sl.InfoContext(ctx, msg, append(args, extractAttrs(ctx)...)...)
}

func (s *SubsystemLogger) DebugContext(ctx context.Context, msg string, args ...any) {
	s.sl.DebugContext(ctx, msg, append(args, extractAttrs(ctx)...)...)
}

func (s *SubsystemLogger) WarnContext(ctx context.Context, msg string, args ...any) {
	s.sl.WarnContext(ctx, msg, append(args, extractAttrs(ctx)...)...)
}

func (s *SubsystemLogger) ErrorContext(ctx context.Context, msg string, args ...any) {
	s.sl.ErrorContext(ctx, msg, append(args, extractAttrs(ctx)...)...)
}

// WithSubsystem returns a bound logger with a component tag
func WithSubsystem(name string) *SubsystemLogger {
	return &SubsystemLogger{sl: globalLogger.With(slog.String("component", name))}
}

// WithUpdateID injects a correlation ID into a context
func WithUpdateID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, UpdateIDKey, id)
}

// extractAttrs pulls tracing IDs from the context
func extractAttrs(ctx context.Context) []any {
	if ctx == nil {
		return nil
	}
	if id, ok := ctx.Value(UpdateIDKey).(string); ok {
		return []any{slog.String("update_id", id)}
	}
	return nil
}

// Structured logging helpers - convenience functions for creating slog attributes
func String(key, value string) slog.Attr {
	return slog.String(key, value)
}

func Int(key string, value int) slog.Attr {
	return slog.Int(key, value)
}

func Int64(key string, value int64) slog.Attr {
	return slog.Int64(key, value)
}

func Bool(key string, value bool) slog.Attr {
	return slog.Bool(key, value)
}

func Any(key string, value any) slog.Attr {
	return slog.Any(key, value)
}

// Package-level structured logging convenience methods
// These are useful when you don't need a SubsystemLogger

// Info logs at Info level with structured attributes
func Info(msg string, args ...any) {
	globalLogger.Info(msg, args...)
}

// Debug logs at Debug level with structured attributes
func Debug(msg string, args ...any) {
	globalLogger.Debug(msg, args...)
}

// Warn logs at Warn level with structured attributes
func Warn(msg string, args ...any) {
	globalLogger.Warn(msg, args...)
}

// Error logs at Error level with structured attributes
func Error(msg string, args ...any) {
	globalLogger.Error(msg, args...)
}
