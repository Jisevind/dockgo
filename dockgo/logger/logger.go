package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/natefinch/lumberjack/v3"
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

	var logOutput io.Writer = os.Stdout

	logFilePath := os.Getenv("LOG_FILE_PATH")
	if logFilePath != "" {
		maxSize := 10
		if val, err := strconv.Atoi(os.Getenv("LOG_MAX_SIZE")); err == nil && val > 0 {
			maxSize = val
		}

		maxBackups := 5
		if val, err := strconv.Atoi(os.Getenv("LOG_MAX_BACKUPS")); err == nil && val > 0 {
			maxBackups = val
		}

		maxAgeDays := 28
		if val, err := strconv.Atoi(os.Getenv("LOG_MAX_AGE")); err == nil && val > 0 {
			maxAgeDays = val
		}

		compressStr := strings.ToLower(os.Getenv("LOG_COMPRESS"))
		compress := compressStr != "false" && compressStr != "0"

		fileLogger, err := lumberjack.NewRoller(
			logFilePath,
			int64(maxSize)*1024*1024,
			&lumberjack.Options{
				MaxBackups: maxBackups,
				MaxAge:     time.Duration(maxAgeDays) * 24 * time.Hour,
				Compress:   compress,
			},
		)

		if err == nil {
			logOutput = io.MultiWriter(os.Stdout, fileLogger)
		} else {
			slog.Warn("Failed to initialize rolling file logger", slog.Any("error", err), slog.String("path", logFilePath))
		}
	}

	if logFormat == "json" || (logFormat == "" && isRunningInDocker()) {
		handler = slog.NewJSONHandler(logOutput, opts)
	} else {
		handler = slog.NewTextHandler(logOutput, opts)
	}

	globalLogger = slog.New(handler)
	slog.SetDefault(globalLogger)
}

func isRunningInDocker() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		return strings.Contains(string(data), "docker") || strings.Contains(string(data), "containerd")
	}
	return false
}

// SetLevel sets the global logging level.
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

// SubsystemLogger wraps slog.Logger with subsystem context.
type SubsystemLogger struct {
	sl *slog.Logger
}

// Info logs a message at Info level.
func (s *SubsystemLogger) Info(msg string, args ...any) {
	s.sl.Info(msg, args...)
}

// Debug logs a message at Debug level.
func (s *SubsystemLogger) Debug(msg string, args ...any) {
	s.sl.Debug(msg, args...)
}

// Warn logs a message at Warn level.
func (s *SubsystemLogger) Warn(msg string, args ...any) {
	s.sl.Warn(msg, args...)
}

// Error logs a message at Error level.
func (s *SubsystemLogger) Error(msg string, args ...any) {
	s.sl.Error(msg, args...)
}

// InfoContext logs a message at Info level with context attributes.
func (s *SubsystemLogger) InfoContext(ctx context.Context, msg string, args ...any) {
	s.sl.InfoContext(ctx, msg, append(args, extractAttrs(ctx)...)...)
}

// DebugContext logs a message at Debug level with context attributes.
func (s *SubsystemLogger) DebugContext(ctx context.Context, msg string, args ...any) {
	s.sl.DebugContext(ctx, msg, append(args, extractAttrs(ctx)...)...)
}

// WarnContext logs a message at Warn level with context attributes.
func (s *SubsystemLogger) WarnContext(ctx context.Context, msg string, args ...any) {
	s.sl.WarnContext(ctx, msg, append(args, extractAttrs(ctx)...)...)
}

// ErrorContext logs a message at Error level with context attributes.
func (s *SubsystemLogger) ErrorContext(ctx context.Context, msg string, args ...any) {
	s.sl.ErrorContext(ctx, msg, append(args, extractAttrs(ctx)...)...)
}

// WithSubsystem returns a logger bound to a component name.
func WithSubsystem(name string) *SubsystemLogger {
	return &SubsystemLogger{sl: globalLogger.With(slog.String("component", name))}
}

// WithUpdateID injects an update correlation ID into context.
func WithUpdateID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, UpdateIDKey, id)
}

func extractAttrs(ctx context.Context) []any {
	if ctx == nil {
		return nil
	}
	if id, ok := ctx.Value(UpdateIDKey).(string); ok {
		return []any{slog.String("update_id", id)}
	}
	return nil
}

// String creates a string attribute.
func String(key, value string) slog.Attr {
	return slog.String(key, value)
}

// Int creates an int attribute.
func Int(key string, value int) slog.Attr {
	return slog.Int(key, value)
}

// Int64 creates an int64 attribute.
func Int64(key string, value int64) slog.Attr {
	return slog.Int64(key, value)
}

// Bool creates a bool attribute.
func Bool(key string, value bool) slog.Attr {
	return slog.Bool(key, value)
}

// Any creates a generic attribute.
func Any(key string, value any) slog.Attr {
	return slog.Any(key, value)
}

// Info logs at Info level with structured attributes.
func Info(msg string, args ...any) {
	globalLogger.Info(msg, args...)
}

// Debug logs at Debug level with structured attributes.
func Debug(msg string, args ...any) {
	globalLogger.Debug(msg, args...)
}

// Warn logs at Warn level with structured attributes.
func Warn(msg string, args ...any) {
	globalLogger.Warn(msg, args...)
}

// Error logs at Error level with structured attributes.
func Error(msg string, args ...any) {
	globalLogger.Error(msg, args...)
}
