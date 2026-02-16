package engine

import (
	"context"
	"dockgo/logger"
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
		logger.Info("Container %s is managed by Compose project '%s'. Proceeding with API recreation (Watchtower-style).", name, project)
		// We do NOT return error anymore. We proceed to recreate via API.
		// This preserves labels so Compose usually accepts the new container.
	}

	logger.Info("Recreating standalone container %s with image %s...", name, imageName)

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
		logger.Warn("Failed to start new container %s. Rolling back...", name)
		_ = d.Client.ContainerRemove(ctx, newContainer.ID, container.RemoveOptions{Force: true})
		_ = d.Client.ContainerRename(ctx, containerID, name)
		_ = d.Client.ContainerStart(ctx, containerID, container.StartOptions{})
		return fmt.Errorf("failed to start new container: %w", err)
	}

	// 6. Verify Health / State
	logger.Info("Waiting for container health/stability (up to 60s)...")

	verifyCtx, cancelVerify := context.WithTimeout(ctx, 60*time.Second)
	defer cancelVerify()

	checkTicker := time.NewTicker(time.Second)
	defer checkTicker.Stop()

	// Refined Logic outside loop is tricky. Let's rewrite the verification block.
	// ...

	// Actual Implementation:
	// Actual Implementation:
	verificationSuccess := false

	// Inspect once to see if healthcheck exists
	startInspect, err := d.Client.ContainerInspect(ctx, newContainer.ID)
	if err == nil && startInspect.State.Health == nil {
		// No healthcheck: Wait 3 seconds, check if running
		time.Sleep(3 * time.Second)
		finalInspect, err := d.Client.ContainerInspect(ctx, newContainer.ID)
		if err == nil && finalInspect.State.Running {
			verificationSuccess = true
		} else {
			if err == nil {
				fmt.Printf("Container stopped running within 3 seconds.\n")
			}
		}
	} else if err == nil {
		// Has healthcheck: Poll till healthy or timeout
		for {
			select {
			case <-verifyCtx.Done():
				logger.Warn("Timed out waiting for healthy status.")
				goto EndVerify
			case <-checkTicker.C:
				inspect, err := d.Client.ContainerInspect(ctx, newContainer.ID)
				if err != nil {
					continue
				}
				if !inspect.State.Running {
					logger.Warn("Container stopped running while waiting for health.")
					goto EndVerify
				}
				if inspect.State.Health.Status == "healthy" {
					verificationSuccess = true
					goto EndVerify
				}
				if inspect.State.Health.Status == "unhealthy" {
					logger.Warn("Container became unhealthy.")
					goto EndVerify
				}
			}
		}
	}
EndVerify:

	// 7. Stability Wait (Post-Verification)
	if verificationSuccess {
		logger.Info("✅ Initial verification passed. Monitoring for 10s stability...")
		select {
		case <-ctx.Done():
			verificationSuccess = false
		case <-time.After(10 * time.Second):
			// Check one last time
			finalInspect, err := d.Client.ContainerInspect(ctx, newContainer.ID)
			if err != nil {
				logger.Error("❌ Failed to inspect container after stability wait: %v", err)
				verificationSuccess = false
			} else if !finalInspect.State.Running {
				logger.Error("❌ Container crashed during stability wait (Exit Code: %d).", finalInspect.State.ExitCode)
				verificationSuccess = false
			} else if finalInspect.State.Health != nil && finalInspect.State.Health.Status == "unhealthy" {
				logger.Error("❌ Container became unhealthy during stability wait.")
				verificationSuccess = false
			} else {
				logger.Info("✅ Container is stable.")
			}
		}
	}

	if !verificationSuccess {
		// Rollback logic
		logger.Warn("Verification failed. Rolling back...")
		// Stop/Remove New
		d.Client.ContainerStop(ctx, newContainer.ID, container.StopOptions{})
		d.Client.ContainerRemove(ctx, newContainer.ID, container.RemoveOptions{Force: true})

		// Restore Old
		renameErr := d.Client.ContainerRename(ctx, containerID, name)
		if renameErr != nil {
			logger.Error("CRITICAL: Failed to rename old container back: %v", renameErr)
			return fmt.Errorf("verification failed and rollback failed (rename): %v", renameErr)
		}

		startErr := d.Client.ContainerStart(ctx, containerID, container.StartOptions{})
		if startErr != nil {
			logger.Error("CRITICAL: Failed to restart old container: %v", startErr)
			return fmt.Errorf("verification failed and rollback failed (start): %v", startErr)
		}

		return fmt.Errorf("new container failed verification (unhealthy or crashed)")
	}

	// 7. Remove old container (Success path)
	logger.Info("New container healthy/stable. Removing old container...")
	err = d.Client.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true})
	if err != nil {
		logger.Warn("Warning: Failed to remove old container: %v", err)
	}

	return nil
}
