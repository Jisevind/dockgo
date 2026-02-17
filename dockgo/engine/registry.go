package engine

import (
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

func NewRegistryClient() *RegistryClient {
	return &RegistryClient{
		cache: make(map[string]cachedDigest),
	}
}

// GetRemoteDigest fetches the digest of the remote image
func (r *RegistryClient) GetRemoteDigest(image string, platform *v1.Platform) (string, error) {
	// 1. Check Cache
	r.mu.RLock()
	if entry, ok := r.cache[image]; ok {
		if time.Now().Before(entry.expiresAt) {
			r.mu.RUnlock()
			return entry.digest, nil
		}
	}
	r.mu.RUnlock()

	options := []crane.Option{
		crane.WithAuthFromKeychain(authn.DefaultKeychain),
	}
	if platform != nil {
		options = append(options, crane.WithPlatform(platform))
	}

	// Check for local/insecure registry
	if strings.Contains(image, "localhost:") || strings.Contains(image, "127.0.0.1:") || strings.Contains(image, "host.docker.internal:") {
		options = append(options, crane.Insecure)
	}

	// Simple normalize: if no tag, assume latest
	// If it's a short name like "alpine", crane expands to "index.docker.io/library/alpine"
	digest, err := crane.Digest(image, options...)
	if err != nil {
		return "", err
	}

	// 2. Update Cache (TTL 10m)
	r.mu.Lock()
	r.cache[image] = cachedDigest{
		digest:    digest,
		expiresAt: time.Now().Add(10 * time.Minute),
	}
	r.mu.Unlock()

	return digest, nil
}

// CheckUpdate compares local image ID (which is properly a digest in newer docker versions or needs resolution)
// Note: Docker's ImageID is "sha256:..." of the config JSON, NOT always the distribution digest.
// We usually need the RepoDigests from ContainerInspect to compare with remote.
func (r *RegistryClient) CheckUpdate(localDigest string, remoteDigest string) bool {
	// Basic string comparison logic
	// We expect "sha256:..." format for both
	return !strings.EqualFold(localDigest, remoteDigest)
}

// Ping checks registry connectivity by attempting to fetch a known image digest
func (r *RegistryClient) Ping() error {
	// We use alpine:latest as a lightweight check
	_, err := r.GetRemoteDigest("library/alpine:latest", nil)
	return err
}
