package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
)

// RecreateContainer handles the stop, rename, create, start flow
func (d *DiscoveryEngine) RecreateContainer(ctx context.Context, containerID string, imageName string, preserveNetwork bool) error {
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

	// --- Config Sanitization ---

	// Override the image in the config to ensure we use the new tag/digest
	json.Config.Image = imageName

	// Reset Hostname if it matches the short ID (meaning it was auto-generated)
	// Docker IDs are hex 64 chars. Short ID is usually 12.
	// json.ID is full ID.
	if strings.HasPrefix(json.ID, json.Config.Hostname) || json.Config.Hostname == json.ID[:12] {
		json.Config.Hostname = "" // Let Docker generate a new one
	}

	// Prepare NetworkingConfig
	// We must not pass read-only fields back to Create.
	// We essentially want coverage of user-defined endpoints settings.
	networkingConfig := &network.NetworkingConfig{
		EndpointsConfig: make(map[string]*network.EndpointSettings),
	}

	for netName, ep := range json.NetworkSettings.Networks {
		// Create a clean EndpointSettings with only input fields
		newEp := &network.EndpointSettings{
			IPAMConfig:          ep.IPAMConfig,
			Links:               ep.Links,
			Aliases:             ep.Aliases,
			NetworkID:           "", // Docker finds it by name, or we can pass it. Name is usually safer/sufficient.
			EndpointID:          "", // Read-only
			Gateway:             "", // Read-only
			IPAddress:           "", // Reset IP to let Docker assign new one, UNLESS we want to enforce static. Valid choice: reset.
			IPPrefixLen:         0,  // Read-only
			IPv6Gateway:         "", // Read-only
			GlobalIPv6Address:   "", // Reset
			GlobalIPv6PrefixLen: 0,  // Read-only
			MacAddress:          "", // Reset MAC to avoid conflict (unless manually set?)
			DriverOpts:          ep.DriverOpts,
		}

		if preserveNetwork {
			// Explicitly preserve MAC and IP
			if ep.MacAddress != "" {
				newEp.MacAddress = ep.MacAddress
			}
			if ep.IPAddress != "" {
				newEp.IPAddress = ep.IPAddress
			}
			if ep.GlobalIPv6Address != "" {
				newEp.GlobalIPv6Address = ep.GlobalIPv6Address
			}

			// Ensure IPAMConfig enforces the static IP if we have one
			if newEp.IPAddress != "" {
				if newEp.IPAMConfig == nil {
					newEp.IPAMConfig = &network.EndpointIPAMConfig{}
				}
				if newEp.IPAMConfig.IPv4Address == "" {
					newEp.IPAMConfig.IPv4Address = newEp.IPAddress
				}
			}
		}

		networkingConfig.EndpointsConfig[netName] = newEp
	}

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
	newContainer, err := d.Client.ContainerCreate(ctx, json.Config, json.HostConfig, networkingConfig, nil, name)
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
