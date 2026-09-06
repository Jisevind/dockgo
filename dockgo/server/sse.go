package server

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"
)

// startSSEHeartbeat runs a 5-second keepalive goroutine that writes SSE comment
// pings to keep the connection alive and detect client disconnects. It stops
// when ctx is cancelled or doneChan is closed. The caller must close doneChan
// and wait for the returned WaitGroup before returning.
func startSSEHeartbeat(ctx context.Context, writeMu *sync.Mutex, w io.Writer, cancel context.CancelFunc, doneChan <-chan struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
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
				if _, err := w.Write([]byte(": ping\n\n")); err != nil {
					writeMu.Unlock()
					cancel()
					return
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				writeMu.Unlock()
			}
		}
	}()
}
