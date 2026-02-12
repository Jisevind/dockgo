package engine

import (
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type RegistryClient struct{}

func NewRegistryClient() *RegistryClient {
	return &RegistryClient{}
}

// GetRemoteDigest fetches the digest of the remote image
func (r *RegistryClient) GetRemoteDigest(image string, platform *v1.Platform) (string, error) {
	options := []crane.Option{
		crane.WithAuthFromKeychain(authn.DefaultKeychain),
	}
	if platform != nil {
		options = append(options, crane.WithPlatform(platform))
	}

	// Simple normalize: if no tag, assume latest (crane handles this mostly, but good to be explicit if needed)
	// If it's a short name like "alpine", crane expands to "index.docker.io/library/alpine"
	digest, err := crane.Digest(image, options...)
	if err != nil {
		return "", err
	}
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
