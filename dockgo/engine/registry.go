package engine

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type cachedDigest struct {
	digest    string
	expiresAt time.Time
}

type RegistryClient struct {
	cache map[string]cachedDigest
	mu    sync.RWMutex
}

// NewRegistryClient creates a registry client with an in-memory digest cache.
func NewRegistryClient() *RegistryClient {
	return &RegistryClient{
		cache: make(map[string]cachedDigest),
	}
}

// GetRemoteDigest resolves a remote image digest.
func (r *RegistryClient) GetRemoteDigest(image string, platform *v1.Platform, force bool) (string, error) {
	cacheKey := image
	if platform != nil {
		cacheKey = fmt.Sprintf("%s|%s/%s", image, platform.OS, platform.Architecture)
	}

	if !force {
		r.mu.RLock()
		if entry, ok := r.cache[cacheKey]; ok {
			if time.Now().Before(entry.expiresAt) {
				r.mu.RUnlock()
				return entry.digest, nil
			}
		}
		r.mu.RUnlock()
	}

	options := []crane.Option{
		crane.WithAuthFromKeychain(authn.DefaultKeychain),
	}
	if platform != nil {
		options = append(options, crane.WithPlatform(platform))
	}

	if strings.Contains(image, "localhost:") || strings.Contains(image, "127.0.0.1:") || strings.Contains(image, "host.docker.internal:") {
		options = append(options, crane.Insecure)
	}

	digest, err := crane.Digest(image, options...)
	if err != nil {
		return "", err
	}

	r.mu.Lock()
	r.cache[cacheKey] = cachedDigest{
		digest:    digest,
		expiresAt: time.Now().Add(10 * time.Minute),
	}
	r.mu.Unlock()

	return digest, nil
}

// CheckUpdate compares local and remote image digests.
func (r *RegistryClient) CheckUpdate(localDigest string, remoteDigest string) bool {
	return !strings.EqualFold(localDigest, remoteDigest)
}

// Ping checks registry reachability with a known image.
func (r *RegistryClient) Ping() error {
	_, err := r.GetRemoteDigest("library/alpine:latest", nil, true)
	return err
}
