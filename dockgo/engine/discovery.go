package engine

import (
	"context"
	"fmt"
	"runtime"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

type DiscoveryEngine struct {
	Client *client.Client
}

// NewDiscoveryEngine creates a Docker discovery client.
func NewDiscoveryEngine() (*DiscoveryEngine, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}

	if _, err := cli.Ping(context.Background()); err != nil {
		if runtime.GOOS == "windows" {
			return nil, fmt.Errorf("failed to connect to Docker (is Docker Desktop running? try setting DOCKER_HOST, e.g., 'npipe:////./pipe/docker_engine'): %v", err)
		}
		return nil, fmt.Errorf("failed to connect to Docker: %w", err)
	}
	return &DiscoveryEngine{Client: cli}, nil
}

// ListContainers returns all containers, including stopped containers.
func (d *DiscoveryEngine) ListContainers(ctx context.Context) ([]types.Container, error) {
	containers, err := d.Client.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, err
	}
	return containers, nil
}

// GetContainerImageDetails returns image metadata for a container.
func (d *DiscoveryEngine) GetContainerImageDetails(ctx context.Context, containerID string) (string, string, []string, string, string, error) {
	cJSON, err := d.Client.ContainerInspect(ctx, containerID)
	if err != nil {
		return "", "", nil, "", "", err
	}

	iJSON, err := d.Client.ImageInspect(ctx, cJSON.Image)
	if err != nil {
		if cJSON.Config != nil {
			return cJSON.Config.Image, cJSON.Image, nil, "", "", nil
		}
		return "", cJSON.Image, nil, "", "", nil
	}

	configImage := ""
	if cJSON.Config != nil {
		configImage = cJSON.Config.Image
	}
	return configImage, cJSON.Image, iJSON.RepoDigests, iJSON.Os, iJSON.Architecture, nil
}

// GetContainerState returns the Docker state of a container.
func (d *DiscoveryEngine) GetContainerState(ctx context.Context, containerID string) (string, error) {
	cJSON, err := d.Client.ContainerInspect(ctx, containerID)
	if err != nil {
		return "", err
	}
	return cJSON.State.Status, nil
}

// StartContainer starts a container by ID.
func (d *DiscoveryEngine) StartContainer(ctx context.Context, containerID string) error {
	return d.Client.ContainerStart(ctx, containerID, container.StartOptions{})
}

// StopContainer stops a container by ID.
func (d *DiscoveryEngine) StopContainer(ctx context.Context, containerID string) error {
	return d.Client.ContainerStop(ctx, containerID, container.StopOptions{})
}

// RestartContainer restarts a container by ID.
func (d *DiscoveryEngine) RestartContainer(ctx context.Context, containerID string) error {
	return d.Client.ContainerRestart(ctx, containerID, container.StopOptions{})
}
