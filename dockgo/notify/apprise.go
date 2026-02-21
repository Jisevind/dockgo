package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"dockgo/logger"
)

type NotificationType string

const (
	TypeInfo    NotificationType = "info"
	TypeSuccess NotificationType = "success"
	TypeWarning NotificationType = "warning"
	TypeFailure NotificationType = "failure" // Will be mapped to "error" for Apprise
)

type Notification struct {
	Title string
	Body  string
	Type  NotificationType
}

type AppriseNotifier struct {
	urls  []string
	queue chan Notification
}

func NewAppriseNotifier(ctx context.Context) *AppriseNotifier {
	notifier := &AppriseNotifier{}

	envUrls := os.Getenv("APPRISE_URL")
	if envUrls == "" {
		return notifier
	}

	var cleanUrls []string
	for _, u := range strings.Split(envUrls, ",") {
		u = strings.TrimSpace(u)
		if u != "" {
			cleanUrls = append(cleanUrls, u)
		}
	}

	if len(cleanUrls) == 0 {
		return notifier
	}

	notifier.urls = cleanUrls
	notifier.queue = make(chan Notification, 100)

	go notifier.worker(ctx)
	return notifier
}

// WaitUntilReady blocks until at least one Apprise URL is reachable or timeout occurs
func (a *AppriseNotifier) WaitUntilReady(timeout time.Duration) bool {
	if a == nil || len(a.urls) == 0 {
		return true
	}

	start := time.Now()
	for time.Since(start) < timeout {
		for _, url := range a.urls {
			targetURL := "http://apprise:8000"

			// If the user specified a full custom apprise host, ping its base
			if !strings.Contains(url, "gotify://") && (strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")) {
				parts := strings.Split(url, "/notify")
				if len(parts) > 0 {
					targetURL = strings.TrimSuffix(parts[0], "/")
				}
			}

			if err := a.ping(targetURL); err == nil {
				return true
			}
		}
		time.Sleep(1 * time.Second)
	}
	return false
}

func (a *AppriseNotifier) ping(url string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func (a *AppriseNotifier) worker(ctx context.Context) {
	client := &http.Client{Timeout: 10 * time.Second}
	for {
		select {
		case <-ctx.Done():
			logger.Debug("Apprise info: worker shutting down")
			return
		case n := <-a.queue:
			a.send(client, n)
		}
	}
}

func (a *AppriseNotifier) send(client *http.Client, n Notification) {
	appriseType := string(n.Type)
	if n.Type == TypeFailure {
		appriseType = "error"
	}

	payload := map[string]interface{}{
		"title":  n.Title,
		"body":   n.Body,
		"type":   appriseType,
		"format": "text",
	}

	for _, url := range a.urls {
		payload["urls"] = url
		b, _ := json.Marshal(payload)

		// IMPORTANT: Ensure we hit the base /notify endpoint exactly
		targetURL := "http://apprise:8000/notify"

		// If the user specified a full custom apprise host, use its base notify
		if !strings.Contains(url, "gotify://") && (strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")) {
			targetURL = strings.TrimSuffix(url, "/all")
			if !strings.Contains(targetURL, "/notify") {
				targetURL = strings.TrimSuffix(targetURL, "/") + "/notify"
			}
		}

		// Simple 3-attempt retry loop
		maxRetries := 3
		for i := 0; i < maxRetries; i++ {
			resp, err := client.Post(targetURL, "application/json", bytes.NewBuffer(b))
			if err != nil {
				if i == maxRetries-1 {
					logger.Error("Apprise: Send failed to %s after %d retries: %v", targetURL, maxRetries, err)
				} else {
					logger.Warn("Apprise: Send failed, retrying (%d/%d)...", i+1, maxRetries)
					time.Sleep(2 * time.Second)
				}
				continue
			}
			resp.Body.Close()
			break // Success
		}
	}
}

func (a *AppriseNotifier) Notify(title, body string, notifType NotificationType) {
	if a == nil || a.queue == nil {
		return
	}
	select {
	case a.queue <- Notification{Title: title, Body: body, Type: notifType}:
	default:
		logger.Warn("Apprise: Queue full")
	}
}
