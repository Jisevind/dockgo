package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
)

// RecreateContainer handles the stop, rename, create, start flow
func (d *DiscoveryEngine) RecreateContainer(ctx context.Context, containerID string, imageName string) error {
	// 1. Inspect the container to get config
	json, err := d.Client.ContainerInspect(ctx, containerID)
	if err != nil {
		return fmt.Errorf("failed to inspect container: %w", err)
	}

	name := json.Name // Name comes with slash, e.g. "/my-container"
	if len(name) > 0 && name[0] == '/' {
		name = name[1:]
	}

	// Check if it's a compose container
	if project, ok := json.Config.Labels["com.docker.compose.project"]; ok {
		fmt.Printf("Container %s is managed by Compose project '%s'. Proceeding with API recreation (Watchtower-style).\n", name, project)
		// We do NOT return error anymore. We proceed to recreate via API.
		// This preserves labels so Compose usually accepts the new container.
	}

	fmt.Printf("Recreating standalone container %s with image %s...\n", name, imageName)

	// Override the image in the config to ensure we use the new tag/digest
	json.Config.Image = imageName

	// 2. Stop container
	timeout := 10 // seconds
	err = d.Client.ContainerStop(ctx, containerID, container.StopOptions{Timeout: &timeout})
	if err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	// 3. Rename old container
	backupName := fmt.Sprintf("%s_old_%d", name, time.Now().Unix())
	err = d.Client.ContainerRename(ctx, containerID, backupName)
	if err != nil {
		return fmt.Errorf("failed to rename container: %w", err)
	}

	// 4. Create new container
	// We need to copy Config, HostConfig, NetworkingConfig
	newContainer, err := d.Client.ContainerCreate(ctx, json.Config, json.HostConfig, &network.NetworkingConfig{EndpointsConfig: json.NetworkSettings.Networks}, nil, name)
	if err != nil {
		// Rollback: Rename old back
		_ = d.Client.ContainerRename(ctx, containerID, name)
		_ = d.Client.ContainerStart(ctx, containerID, container.StartOptions{})
		return fmt.Errorf("failed to create new container: %w", err)
	}

	// 5. Start new container
	err = d.Client.ContainerStart(ctx, newContainer.ID, container.StartOptions{})
	if err != nil {
		// Rollback: Remove new, rename old back, start old
		fmt.Printf("Failed to start new container %s. Rolling back...\n", name)
		_ = d.Client.ContainerRemove(ctx, newContainer.ID, container.RemoveOptions{Force: true})
		_ = d.Client.ContainerRename(ctx, containerID, name)
		_ = d.Client.ContainerStart(ctx, containerID, container.StartOptions{})
		return fmt.Errorf("failed to start new container: %w", err)
	}

	// 6. Remove old container (Success path)
	fmt.Printf("New container started successfully. Removing old container...\n")
	err = d.Client.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true})
	if err != nil {
		fmt.Printf("Warning: Failed to remove old container: %v\n", err)
		// Not a fatal error, update succeeded
	}

	return nil
}
