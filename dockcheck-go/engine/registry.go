package engine

import (
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
)

type RegistryClient struct{}

func NewRegistryClient() *RegistryClient {
	return &RegistryClient{}
}

// GetRemoteDigest fetches the digest of the remote image
func (r *RegistryClient) GetRemoteDigest(image string) (string, error) {
	// Simple normalize: if no tag, assume latest (crane handles this mostly, but good to be explicit if needed)
	// If it's a short name like "alpine", crane expands to "index.docker.io/library/alpine"
	digest, err := crane.Digest(image)
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
