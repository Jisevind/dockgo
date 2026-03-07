package engine

import (
	"context"
	"dockgo/logger"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
)

var engineLog = logger.WithSubsystem("engine")

// RecreateContainer recreates a standalone container with its current config.
func (d *DiscoveryEngine) RecreateContainer(ctx context.Context, containerID string, imageName string, preserveNetwork bool, emitLog func(string)) error {
	if emitLog == nil {
		emitLog = func(string) {}
	}
	json, err := d.Client.ContainerInspect(ctx, containerID)
	if err != nil {
		return fmt.Errorf("failed to inspect container: %w", err)
	}

	name := json.Name
	if len(name) > 0 && name[0] == '/' {
		name = name[1:]
	}

	if _, ok := json.Config.Labels["com.docker.compose.project"]; ok {
		err := fmt.Errorf("refusing to recreate Compose-managed container via standalone API")
		engineLog.ErrorContext(ctx, err.Error(),
			logger.String("container", name),
		)
		return err
	}

	startMsg := fmt.Sprintf("Recreating standalone container %s with image %s...", name, imageName)
	engineLog.InfoContext(ctx, startMsg,
		logger.String("container", name),
		logger.String("image", imageName),
	)
	emitLog(startMsg)


	json.Config.Image = imageName

	if strings.HasPrefix(json.ID, json.Config.Hostname) || json.Config.Hostname == json.ID[:12] {
		json.Config.Hostname = ""
	}

	networkingConfig := &network.NetworkingConfig{
		EndpointsConfig: make(map[string]*network.EndpointSettings),
	}

	for netName, ep := range json.NetworkSettings.Networks {
		newEp := &network.EndpointSettings{
			IPAMConfig:          ep.IPAMConfig,
			Links:               ep.Links,
			Aliases:             ep.Aliases,
			NetworkID:           "",
			EndpointID:          "",
			Gateway:             "",
			IPAddress:           "",
			IPPrefixLen:         0,
			IPv6Gateway:         "",
			GlobalIPv6Address:   "",
			GlobalIPv6PrefixLen: 0,
			MacAddress:          "",
			DriverOpts:          ep.DriverOpts,
		}

		if preserveNetwork {
			if ep.MacAddress != "" {
				newEp.MacAddress = ep.MacAddress
			}

			if netName != "bridge" {
				if ep.IPAddress != "" {
					newEp.IPAddress = ep.IPAddress
				}
				if ep.GlobalIPv6Address != "" {
					newEp.GlobalIPv6Address = ep.GlobalIPv6Address
				}

				if newEp.IPAddress != "" {
					if newEp.IPAMConfig == nil {
						newEp.IPAMConfig = &network.EndpointIPAMConfig{}
					}
					if newEp.IPAMConfig.IPv4Address == "" {
						newEp.IPAMConfig.IPv4Address = newEp.IPAddress
					}
				}
			}
		}

		networkingConfig.EndpointsConfig[netName] = newEp
	}

	timeout := 10
	if v := os.Getenv("DOCKGO_STOP_TIMEOUT"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			timeout = parsed
		}
	}
	err = d.Client.ContainerStop(ctx, containerID, container.StopOptions{Timeout: &timeout})
	if err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	backupName := fmt.Sprintf("%s_old_%d", name, time.Now().Unix())
	err = d.Client.ContainerRename(ctx, containerID, backupName)
	if err != nil {
		return fmt.Errorf("failed to rename container: %w", err)
	}

	newContainer, err := d.Client.ContainerCreate(ctx, json.Config, json.HostConfig, networkingConfig, nil, name)
	if err != nil {
		_ = d.Client.ContainerRename(ctx, containerID, name)
		_ = d.Client.ContainerStart(ctx, containerID, container.StartOptions{})
		return fmt.Errorf("failed to create new container: %w", err)
	}

	err = d.Client.ContainerStart(ctx, newContainer.ID, container.StartOptions{})
	if err != nil {
		failMsg := fmt.Sprintf("Failed to start new container %s. Rolling back...", name)
		engineLog.WarnContext(ctx, failMsg,
			logger.String("container", name),
		)
		emitLog("⚠️ " + failMsg)
		_ = d.Client.ContainerRemove(ctx, newContainer.ID, container.RemoveOptions{Force: true})
		_ = d.Client.ContainerRename(ctx, containerID, name)
		_ = d.Client.ContainerStart(ctx, containerID, container.StartOptions{})
		return fmt.Errorf("failed to start new container: %w", err)
	}

	healthTimeout := 60
	if v := os.Getenv("DOCKGO_HEALTH_TIMEOUT"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			healthTimeout = parsed
		}
	}

	initialCheck := 10
	if v := os.Getenv("DOCKGO_INITIAL_RUNTIME_CHECK"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			initialCheck = parsed
		}
	}
	waitMsg := fmt.Sprintf("Waiting for container health/stability (up to %ds)...", healthTimeout)
	engineLog.InfoContext(ctx, waitMsg,
		logger.String("container", name),
	)
	emitLog("⏳ " + waitMsg)

	verifyCtx, cancelVerify := context.WithTimeout(ctx, time.Duration(healthTimeout)*time.Second)
	defer cancelVerify()

	checkTicker := time.NewTicker(time.Second)
	defer checkTicker.Stop()

	verificationSuccess := false

	startInspect, err := d.Client.ContainerInspect(ctx, newContainer.ID)
	if err != nil {
		engineLog.WarnContext(ctx, "Failed to inspect container for healthcheck status",
			logger.String("container", name),
			logger.Any("error", err),
		)
		goto EndVerify
	}

	if startInspect.State.Health == nil {
		verificationSuccess = true
		for i := 0; i < initialCheck; i++ {
			if ctx.Err() != nil {
				verificationSuccess = false
				engineLog.WarnContext(ctx, "Context cancelled during initial runtime check",
					logger.String("container", name),
				)
				break
			}
			time.Sleep(1 * time.Second)
			finalInspect, err := d.Client.ContainerInspect(ctx, newContainer.ID)
			if err != nil || !finalInspect.State.Running {
				verificationSuccess = false
				engineLog.WarnContext(ctx, fmt.Sprintf("Container stopped running within the first %d seconds.", initialCheck),
					logger.String("container", name),
				)
				break
			}
		}
	} else if err == nil {
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

	if verificationSuccess {
		stabilityWindow := 20
		if v := os.Getenv("DOCKGO_STABILITY_WINDOW"); v != "" {
			if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
				stabilityWindow = parsed
			}
		}
		stableMsg := fmt.Sprintf("Initial verification passed. Monitoring for %ds stability...", stabilityWindow)
		engineLog.InfoContext(ctx, stableMsg,
			logger.String("container", name),
		)
		emitLog("✅ " + stableMsg)
		select {
		case <-ctx.Done():
			verificationSuccess = false
		case <-time.After(time.Duration(stabilityWindow) * time.Second):
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
				emitLog("✅ Container is stable.")
			}
		}
	}

	if !verificationSuccess {
		engineLog.WarnContext(ctx, "Verification failed. Rolling back",
			logger.String("container", name),
		)
		emitLog("❌ Verification failed. Rolling back...")
		if err := d.Client.ContainerStop(ctx, newContainer.ID, container.StopOptions{}); err != nil {
			engineLog.WarnContext(ctx, "Failed to stop new container during rollback", logger.Any("error", err))
		}
		if err := d.Client.ContainerRemove(ctx, newContainer.ID, container.RemoveOptions{Force: true}); err != nil {
			engineLog.WarnContext(ctx, "Failed to remove new container during rollback", logger.Any("error", err))
		}

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

	cleanupMsg := "New container healthy/stable. Removing old container..."
	engineLog.InfoContext(ctx, cleanupMsg,
		logger.String("container", name),
	)
	emitLog("🧹 " + cleanupMsg)
	err = d.Client.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true})
	if err != nil {
		engineLog.WarnContext(ctx, "Failed to remove old container",
			logger.String("container", name),
			logger.Any("error", err),
		)
	}

	return nil
}
