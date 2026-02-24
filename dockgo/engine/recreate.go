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

var engineLog = logger.WithSubsystem("engine")

// RecreateContainer handles the stop, rename, create, start flow
func (d *DiscoveryEngine) RecreateContainer(ctx context.Context, containerID string, imageName string, preserveNetwork bool, logCb func(string)) error {
	if logCb == nil {
		logCb = func(string) {}
	}
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
		msg := fmt.Sprintf("Container %s is managed by Compose project '%s'. Proceeding with API recreation (Watchtower-style).", name, project)
		engineLog.InfoContext(ctx, msg,
			logger.String("container", name),
			logger.String("project", project),
		)
		logCb(msg)
	}

	startMsg := fmt.Sprintf("Recreating standalone container %s with image %s...", name, imageName)
	engineLog.InfoContext(ctx, startMsg,
		logger.String("container", name),
		logger.String("image", imageName),
	)
	logCb(startMsg)

	// --- Config Sanitization ---

	// Override the image in the config to ensure we use the new tag/digest
	json.Config.Image = imageName

	// Reset Hostname if it matches the short ID (indicating it was auto-generated).
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
		failMsg := fmt.Sprintf("Failed to start new container %s. Rolling back...", name)
		engineLog.WarnContext(ctx, failMsg,
			logger.String("container", name),
		)
		logCb("⚠️ " + failMsg)
		_ = d.Client.ContainerRemove(ctx, newContainer.ID, container.RemoveOptions{Force: true})
		_ = d.Client.ContainerRename(ctx, containerID, name)
		_ = d.Client.ContainerStart(ctx, containerID, container.StartOptions{})
		return fmt.Errorf("failed to start new container: %w", err)
	}

	// 6. Verify Health / State
	waitMsg := "Waiting for container health/stability (up to 60s)..."
	engineLog.InfoContext(ctx, waitMsg,
		logger.String("container", name),
	)
	logCb("⏳ " + waitMsg)

	verifyCtx, cancelVerify := context.WithTimeout(ctx, 60*time.Second)
	defer cancelVerify()

	checkTicker := time.NewTicker(time.Second)
	defer checkTicker.Stop()

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
				engineLog.WarnContext(ctx, "Container stopped running within 3 seconds.",
					logger.String("container", name),
				)
			}
		}
	} else if err == nil {
		// Has healthcheck: Poll till healthy or timeout
		for {
			select {
			case <-verifyCtx.Done():
				engineLog.WarnContext(ctx, "Timed out waiting for healthy status.",
					logger.String("container", name),
				)
				goto EndVerify
			case <-checkTicker.C:
				inspect, err := d.Client.ContainerInspect(ctx, newContainer.ID)
				if err != nil {
					continue
				}
				if !inspect.State.Running {
					engineLog.WarnContext(ctx, "Container stopped running while waiting for health.",
						logger.String("container", name),
					)
					goto EndVerify
				}
				if inspect.State.Health.Status == "healthy" {
					verificationSuccess = true
					goto EndVerify
				}
				if inspect.State.Health.Status == "unhealthy" {
					engineLog.WarnContext(ctx, "Container became unhealthy.",
						logger.String("container", name),
					)
					goto EndVerify
				}
			}
		}
	}
EndVerify:

	// 7. Stability Wait (Post-Verification)
	if verificationSuccess {
		stableMsg := "Initial verification passed. Monitoring for 20s stability..."
		engineLog.InfoContext(ctx, stableMsg,
			logger.String("container", name),
		)
		logCb("✅ " + stableMsg)
		select {
		case <-ctx.Done():
			verificationSuccess = false
		case <-time.After(20 * time.Second):
			// Check one last time
			finalInspect, err := d.Client.ContainerInspect(ctx, newContainer.ID)
			if err != nil {
				engineLog.ErrorContext(ctx, "Failed to inspect container after stability wait",
					logger.String("container", name),
					logger.Any("error", err),
				)
				verificationSuccess = false
			} else if !finalInspect.State.Running {
				engineLog.ErrorContext(ctx, "Container crashed during stability wait",
					logger.String("container", name),
					logger.Int("exit_code", finalInspect.State.ExitCode),
				)
				verificationSuccess = false
			} else if finalInspect.State.Health != nil && finalInspect.State.Health.Status == "unhealthy" {
				engineLog.ErrorContext(ctx, "Container became unhealthy during stability wait",
					logger.String("container", name),
				)
				verificationSuccess = false
			} else {
				engineLog.InfoContext(ctx, "Container is stable",
					logger.String("container", name),
				)
				logCb("✅ Container is stable.")
			}
		}
	}

	if !verificationSuccess {
		// Rollback logic
		engineLog.WarnContext(ctx, "Verification failed. Rolling back",
			logger.String("container", name),
		)
		logCb("❌ Verification failed. Rolling back...")
		// Stop/Remove New
		_ = d.Client.ContainerStop(ctx, newContainer.ID, container.StopOptions{})
		_ = d.Client.ContainerRemove(ctx, newContainer.ID, container.RemoveOptions{Force: true})

		// Restore Old
		renameErr := d.Client.ContainerRename(ctx, containerID, name)
		if renameErr != nil {
			engineLog.ErrorContext(ctx, "CRITICAL: Failed to rename old container back",
				logger.String("container", name),
				logger.Any("error", renameErr),
			)
			return fmt.Errorf("verification failed and rollback failed (rename): %v", renameErr)
		}

		startErr := d.Client.ContainerStart(ctx, containerID, container.StartOptions{})
		if startErr != nil {
			engineLog.ErrorContext(ctx, "CRITICAL: Failed to restart old container",
				logger.String("container", name),
				logger.Any("error", startErr),
			)
			return fmt.Errorf("verification failed and rollback failed (start): %v", startErr)
		}

		return fmt.Errorf("new container failed verification (unhealthy or crashed)")
	}

	// 7. Remove old container (Success path)
	cleanupMsg := "New container healthy/stable. Removing old container..."
	engineLog.InfoContext(ctx, cleanupMsg,
		logger.String("container", name),
	)
	logCb("🧹 " + cleanupMsg)
	err = d.Client.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true})
	if err != nil {
		engineLog.WarnContext(ctx, "Failed to remove old container",
			logger.String("container", name),
			logger.Any("error", err),
		)
	}

	return nil
}
