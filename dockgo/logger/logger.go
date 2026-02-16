package logger

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

var (
	currentLevel = LevelInfo
	mu           sync.RWMutex
)

func SetLevel(levelStr string) {
	mu.Lock()
	defer mu.Unlock()
	switch strings.ToLower(levelStr) {
	case "debug":
		currentLevel = LevelDebug
	case "info":
		currentLevel = LevelInfo
	case "warn":
		currentLevel = LevelWarn
	case "error":
		currentLevel = LevelError
	default:
		currentLevel = LevelInfo // Default
	}
}

func log(level Level, prefix, format string, args ...interface{}) {
	mu.RLock()
	if level < currentLevel {
		mu.RUnlock()
		return
	}
	mu.RUnlock()

	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format(time.RFC3339)
	fmt.Printf("%s [%s] %s\n", timestamp, prefix, msg)
}

func Debug(format string, args ...interface{}) {
	log(LevelDebug, "DEBUG", format, args...)
}

func Info(format string, args ...interface{}) {
	log(LevelInfo, "INFO", format, args...)
}

func Warn(format string, args ...interface{}) {
	log(LevelWarn, "WARN", format, args...)
}

func Error(format string, args ...interface{}) {
	log(LevelError, "ERROR", format, args...)
}
