package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"dockgo/api"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
)

// containerOverviewConcurrency bounds the number of parallel inspect/stats
// calls so a host with many containers does not overwhelm the daemon.
const containerOverviewConcurrency = 8

// containerStatsTimeout bounds one container's stats call.
const containerStatsTimeout = 10 * time.Second

// ListContainerOverviews returns the containers page rows: container state plus
// a one-shot snapshot of CPU, memory, network, and disk usage.
func (d *DiscoveryEngine) ListContainerOverviews(ctx context.Context) ([]api.ContainerOverview, error) {
	containers, err := d.ListContainers(ctx)
	if err != nil {
		return nil, err
	}

	visible := make([]container.Summary, 0, len(containers))
	for _, c := range containers {
		if len(c.Names) > 0 && strings.Contains(c.Names[0], "_old_") {
			continue
		}
		visible = append(visible, c)
	}

	now := time.Now()
	results := make([]api.ContainerOverview, len(visible))
	sem := make(chan struct{}, containerOverviewConcurrency)
	var wg sync.WaitGroup

	for i, summary := range visible {
		wg.Add(1)
		go func(i int, summary container.Summary) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			inspect, err := d.Client.ContainerInspect(ctx, summary.ID)
			if err != nil {
				inspect = container.InspectResponse{}
			}

			var stats *container.StatsResponse
			if summary.State == container.StateRunning {
				statsCtx, cancel := context.WithTimeout(ctx, containerStatsTimeout)
				defer cancel()
				if reader, err := d.Client.ContainerStatsOneShot(statsCtx, summary.ID); err == nil {
					var decoded container.StatsResponse
					decodeErr := json.NewDecoder(reader.Body).Decode(&decoded)
					_ = reader.Body.Close()
					if decodeErr == nil {
						stats = &decoded
					}
				}
			}

			results[i] = buildContainerOverview(summary, inspect, stats, now)
		}(i, summary)
	}
	wg.Wait()

	sortContainerOverviews(results)
	return results, nil
}

// buildContainerOverview merges the list summary, inspect data, and an optional
// stats sample into one dashboard row.
func buildContainerOverview(summary container.Summary, inspect container.InspectResponse, stats *container.StatsResponse, now time.Time) api.ContainerOverview {
	row := api.ContainerOverview{
		ID:             summary.ID,
		Image:          summary.Image,
		State:          summary.State,
		Ports:          []string{},
		ComposeProject: summary.Labels[composeProjectLabel],
		Networks:       []string{},
		Volumes:        []string{},
	}
	if len(summary.Names) > 0 {
		row.Name = strings.TrimPrefix(summary.Names[0], "/")
	}

	if inspect.ContainerJSONBase != nil {
		if inspect.State != nil {
			if inspect.State.Status != "" {
				row.State = string(inspect.State.Status)
			}
			if inspect.State.Health != nil {
				row.Health = string(inspect.State.Health.Status)
			}
			row.UptimeSeconds, row.UptimeAgo = containerUptime(
				inspect.State, now,
			)
		}
		row.RestartCount = inspect.RestartCount
	}

	if inspect.NetworkSettings != nil {
		row.IP = containerIPAddress(inspect.NetworkSettings.Networks)
	}

	row.Ports = containerPorts(summary.Ports)

	if summary.NetworkSettings != nil {
		for name := range summary.NetworkSettings.Networks {
			if name != "" {
				row.Networks = append(row.Networks, name)
			}
		}
		sort.Strings(row.Networks)
	}

	seenVolumes := make(map[string]bool)
	for _, mount := range summary.Mounts {
		if mount.Type != "volume" || mount.Name == "" || seenVolumes[mount.Name] {
			continue
		}
		seenVolumes[mount.Name] = true
		row.Volumes = append(row.Volumes, mount.Name)
	}
	sort.Strings(row.Volumes)

	if stats != nil {
		applyContainerStats(&row, stats)
	}
	return row
}

func containerUptime(state *container.State, now time.Time) (int64, bool) {
	parse := func(value string) (time.Time, bool) {
		if value == "" {
			return time.Time{}, false
		}
		t, err := time.Parse(time.RFC3339Nano, value)
		if err != nil || t.IsZero() || t.Year() <= 1 {
			return time.Time{}, false
		}
		return t, true
	}

	if state.Running || string(state.Status) == container.StateRunning {
		if started, ok := parse(state.StartedAt); ok {
			return int64(now.Sub(started).Seconds()), false
		}
		return 0, false
	}
	if finished, ok := parse(state.FinishedAt); ok {
		return int64(now.Sub(finished).Seconds()), true
	}
	return 0, false
}

func containerIPAddress(networks map[string]*network.EndpointSettings) string {
	names := make([]string, 0, len(networks))
	for name := range networks {
		names = append(names, name)
	}
	sort.Strings(names)

	ips := make([]string, 0, len(names))
	for _, name := range names {
		endpoint := networks[name]
		if endpoint == nil || endpoint.IPAddress == "" {
			continue
		}
		ips = append(ips, endpoint.IPAddress)
	}
	return strings.Join(ips, ", ")
}

func containerPorts(ports []container.Port) []string {
	result := make([]string, 0, len(ports))
	seen := make(map[string]bool)
	for _, port := range ports {
		if port.PrivatePort == 0 {
			continue
		}
		value := strconv.Itoa(int(port.PrivatePort))
		if port.PublicPort > 0 {
			value = fmt.Sprintf("%d:%d", port.PublicPort, port.PrivatePort)
		}
		if seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func applyContainerStats(row *api.ContainerOverview, stats *container.StatsResponse) {
	cpuDelta := float64(stats.CPUStats.CPUUsage.TotalUsage) -
		float64(stats.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(stats.CPUStats.SystemUsage) -
		float64(stats.PreCPUStats.SystemUsage)
	if cpuDelta > 0 && systemDelta > 0 {
		onlineCPUs := int(stats.CPUStats.OnlineCPUs)
		if onlineCPUs == 0 {
			onlineCPUs = len(stats.CPUStats.CPUUsage.PercpuUsage)
		}
		if onlineCPUs == 0 {
			onlineCPUs = 1
		}
		row.CPUPercent = cpuDelta / systemDelta * float64(onlineCPUs) * 100
	}

	row.MemoryLimit = stats.MemoryStats.Limit
	row.MemoryUsed = stats.MemoryStats.Usage
	cache := stats.MemoryStats.Stats["total_inactive_file"]
	if cache == 0 {
		cache = stats.MemoryStats.Stats["inactive_file"]
	}
	if cache == 0 {
		cache = stats.MemoryStats.Stats["cache"]
	}
	if cache < row.MemoryUsed {
		row.MemoryUsed -= cache
	}

	for _, network := range stats.Networks {
		row.NetRx += network.RxBytes
		row.NetTx += network.TxBytes
	}

	for _, entry := range stats.BlkioStats.IoServiceBytesRecursive {
		switch strings.ToLower(entry.Op) {
		case "read":
			row.DiskRead += entry.Value
		case "write":
			row.DiskWrite += entry.Value
		}
	}
}

func sortContainerOverviews(rows []api.ContainerOverview) {
	sort.Slice(rows, func(i, j int) bool {
		left := strings.ToLower(rows[i].Name)
		right := strings.ToLower(rows[j].Name)
		if left != right {
			return left < right
		}
		return rows[i].ID < rows[j].ID
	})
}
