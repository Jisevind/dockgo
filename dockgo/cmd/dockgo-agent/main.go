package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"dockgo/agent"
	"dockgo/logger"
)

func main() {
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel != "" {
		logger.SetLevel(logLevel)
	}

	fs := flag.NewFlagSet("dockgo-agent", flag.ExitOnError)
	serverURL := fs.String("server", "", "Server URL (ws:// or wss://), default: $DOCKGO_SERVER_URL")
	agentKey := fs.String("key", "", "Agent registration key, default: $AGENT_KEY")
	agentName := fs.String("name", "", "Agent display name, default: $AGENT_NAME or hostname")
	_ = fs.Parse(os.Args[1:])

	url := *serverURL
	if url == "" {
		url = os.Getenv("DOCKGO_SERVER_URL")
	}
	key := *agentKey
	if key == "" {
		key = os.Getenv("AGENT_KEY")
	}
	name := *agentName
	if name == "" {
		name = os.Getenv("AGENT_NAME")
	}

	if url == "" {
		fmt.Fprintln(os.Stderr, "DOCKGO_SERVER_URL (or --server) is required")
		os.Exit(1)
	}
	if key == "" {
		fmt.Fprintln(os.Stderr, "AGENT_KEY (or --key) is required")
		os.Exit(1)
	}

	reconnectMin := parseDuration("AGENT_RECONNECT_MIN", 5*time.Second)
	reconnectMax := parseDuration("AGENT_RECONNECT_MAX", 60*time.Second)
	reconnectMult := parseFloat("AGENT_RECONNECT_MULT", 2.0)
	heartbeat := parseDuration("AGENT_HEARTBEAT_INTERVAL", 30*time.Second)
	stackStorePath := os.Getenv("STACK_STORE_PATH")
	if stackStorePath == "" {
		stackStorePath = "/app/data/agent_stacks.json"
	}

	agentImpl, err := agent.New(agent.Config{
		ServerURL:         url,
		AgentKey:          key,
		AgentName:         name,
		ReconnectMin:      reconnectMin,
		ReconnectMax:      reconnectMax,
		ReconnectMult:     reconnectMult,
		HeartbeatInterval: heartbeat,
		StackStorePath:    stackStorePath,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize agent: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("DockGo agent starting",
		logger.String("server_url", url),
	)

	go func() {
		<-ctx.Done()
		logger.Info("Shutdown signal received, stopping agent")
		agentImpl.Stop()
	}()

	if err := agentImpl.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Agent failed: %v\n", err)
		os.Exit(1)
	}
}

func parseDuration(envKey string, fallback time.Duration) time.Duration {
	if raw := os.Getenv(envKey); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			return d
		}
		logger.Warn("Invalid duration env, using default",
			logger.String("env", envKey),
			logger.String("value", raw),
		)
	}
	return fallback
}

func parseFloat(envKey string, fallback float64) float64 {
	if raw := os.Getenv(envKey); raw != "" {
		if v, err := strconv.ParseFloat(raw, 64); err == nil && v > 0 {
			return v
		}
		logger.Warn("Invalid float env, using default",
			logger.String("env", envKey),
			logger.String("value", raw),
		)
	}
	return fallback
}
