package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
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
	urls   []string
	queue  chan Notification
	closed bool
	mu     sync.Mutex
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

func getAppriseHost() string {
	host := os.Getenv("APPRISE_API_HOST")
	if host == "" {
		return "http://apprise:8000"
	}
	return strings.TrimSuffix(host, "/")
}

// normalizeAppriseTarget determines the absolute base HTTP URL to reach the Apprise sidecar
func normalizeAppriseTarget(url string) string {
	targetURL := getAppriseHost()

	// If the user specified a full custom apprise host remotely via an http prefix, use its base
	if !strings.Contains(url, "gotify://") && (strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")) {
		targetURL = strings.TrimSuffix(url, "/all")
		parts := strings.Split(targetURL, "/notify")
		if len(parts) > 0 {
			targetURL = strings.TrimSuffix(parts[0], "/")
		}
	}

	return targetURL
}

// WaitUntilReady blocks until at least one Apprise URL is reachable or timeout occurs
func (a *AppriseNotifier) WaitUntilReady(timeout time.Duration) bool {
	if a == nil || len(a.urls) == 0 {
		return true
	}

	start := time.Now()
	for time.Since(start) < timeout {
		for _, url := range a.urls {
			targetURL := normalizeAppriseTarget(url)

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
			logger.Debug("Apprise info: worker shutting down, draining queue...")
			a.mu.Lock()
			a.closed = true
			close(a.queue)
			a.mu.Unlock()

			// Drain remaining messages directly from the closed channel
			for n := range a.queue {
				a.send(client, n)
			}
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

	for _, url := range a.urls {
		payload := map[string]interface{}{
			"title":  n.Title,
			"body":   n.Body,
			"type":   appriseType,
			"format": "text",
			"urls":   url,
		}

		b, _ := json.Marshal(payload)

		targetURL := normalizeAppriseTarget(url) + "/notify"

		// Simple 3-attempt retry loop
		maxRetries := 3
		for i := 0; i < maxRetries; i++ {
			resp, err := client.Post(targetURL, "application/json", bytes.NewBuffer(b))
			if err != nil {
				if i == maxRetries-1 {
					logger.Error("Apprise: Send failed to %s after %d retries: %v", targetURL, maxRetries, err)
				} else {
					logger.Warn("Apprise: Send failed, retrying (%d/%d)...", i+1, maxRetries)
					jitter := time.Duration(rand.Intn(1000)) * time.Millisecond
					time.Sleep(2*time.Second + jitter)
				}
				continue
			}

			if resp.StatusCode >= 300 {
				resp.Body.Close()
				if i == maxRetries-1 {
					logger.Error("Apprise: Send failed to %s after %d retries: status %d", targetURL, maxRetries, resp.StatusCode)
				} else {
					logger.Warn("Apprise: Send failed (status %d), retrying (%d/%d)...", resp.StatusCode, i+1, maxRetries)
					jitter := time.Duration(rand.Intn(1000)) * time.Millisecond
					time.Sleep(2*time.Second + jitter)
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
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.mu.Unlock()

	n := Notification{Title: title, Body: body, Type: notifType}

	for {
		select {
		case a.queue <- n:
			return // Successfully queued
		default:
			// Queue is full, drop the oldest message to make room
			select {
			case dropped := <-a.queue:
				logger.Warn("Apprise: Queue full, dropping oldest notification: %s", dropped.Title)
			default:
				// The worker grabbed it in the microsecond between selects, loop again
			}
		}
	}
}
