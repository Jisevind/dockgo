package logger

import (
	"context"
	"fmt"
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
	if strings.ToLower(os.Getenv("LOG_FORMAT")) == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	globalLogger = slog.New(handler)
	slog.SetDefault(globalLogger)
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

// WithSubsystem returns a bound logger with a component tag
func WithSubsystem(name string) *slog.Logger {
	return globalLogger.With(slog.String("component", name))
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

// Contextual Logging Helpers

func InfoCtx(ctx context.Context, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	globalLogger.InfoContext(ctx, msg, extractAttrs(ctx)...)
}

func DebugCtx(ctx context.Context, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	globalLogger.DebugContext(ctx, msg, extractAttrs(ctx)...)
}

func WarnCtx(ctx context.Context, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	globalLogger.WarnContext(ctx, msg, extractAttrs(ctx)...)
}

func ErrorCtx(ctx context.Context, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	globalLogger.ErrorContext(ctx, msg, extractAttrs(ctx)...)
}

// Legacy Printf-style Wrappers (for backwards compatibility)

func Debug(format string, args ...interface{}) {
	globalLogger.Debug(fmt.Sprintf(format, args...))
}

func Info(format string, args ...interface{}) {
	globalLogger.Info(fmt.Sprintf(format, args...))
}

func Warn(format string, args ...interface{}) {
	globalLogger.Warn(fmt.Sprintf(format, args...))
}

func Error(format string, args ...interface{}) {
	globalLogger.Error(fmt.Sprintf(format, args...))
}
