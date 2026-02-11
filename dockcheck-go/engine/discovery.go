package engine

import (
	"context"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

type DiscoveryEngine struct {
	Client *client.Client
}

func NewDiscoveryEngine() (*DiscoveryEngine, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	return &DiscoveryEngine{Client: cli}, nil
}

func (d *DiscoveryEngine) ListContainers(ctx context.Context) ([]types.Container, error) {
	containers, err := d.Client.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, err
	}
	return containers, nil
}

// GetContainerImageDetails returns the image name, ID, and RepoDigests
func (d *DiscoveryEngine) GetContainerImageDetails(ctx context.Context, containerID string) (string, string, []string, error) {
	cJSON, err := d.Client.ContainerInspect(ctx, containerID)
	if err != nil {
		return "", "", nil, err
	}

	// Image field in ContainerJSON is the ImageID
	iJSON, _, err := d.Client.ImageInspectWithRaw(ctx, cJSON.Image)
	if err != nil {
		// If image inspect fails, we return what we have
		return cJSON.Config.Image, cJSON.Image, nil, nil
	}

	return cJSON.Config.Image, cJSON.Image, iJSON.RepoDigests, nil
}

// GetContainerState returns the state string of a container (e.g. "running", "exited")
func (d *DiscoveryEngine) GetContainerState(ctx context.Context, containerID string) (string, error) {
	cJSON, err := d.Client.ContainerInspect(ctx, containerID)
	if err != nil {
		return "", err
	}
	return cJSON.State.Status, nil
}
