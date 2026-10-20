package engine

import (
	"context"
	"sort"

	"dockgo/api"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
)

// ListNetworks returns the Docker networks visible to the daemon, sorted by
// name so the dashboard table has a stable order.
func (d *DiscoveryEngine) ListNetworks(ctx context.Context) ([]api.DockerNetwork, error) {
	networks, err := d.Client.NetworkList(ctx, network.ListOptions{})
	if err != nil {
		return nil, err
	}

	// NetworkList leaves Containers empty, so derive per-network counts from
	// the container summaries instead of inspecting every network.
	containers, err := d.Client.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, err
	}

	return summarizeNetworks(networks, countContainersByNetwork(containers)), nil
}

// countContainersByNetwork maps network IDs to the number of containers
// attached to them. A container can be attached to several networks and counts
// once for each.
func countContainersByNetwork(containers []container.Summary) map[string]int {
	counts := make(map[string]int)
	for _, c := range containers {
		if c.NetworkSettings == nil {
			continue
		}
		for _, endpoint := range c.NetworkSettings.Networks {
			if endpoint == nil || endpoint.NetworkID == "" {
				continue
			}
			counts[endpoint.NetworkID]++
		}
	}
	return counts
}

// summarizeNetworks converts Docker's network resources into the flat shape the
// dashboard renders.
func summarizeNetworks(summaries []network.Summary, containerCounts map[string]int) []api.DockerNetwork {
	result := make([]api.DockerNetwork, 0, len(summaries))
	for _, n := range summaries {
		subnets := make([]string, 0, len(n.IPAM.Config))
		gateways := make([]string, 0, len(n.IPAM.Config))
		for _, cfg := range n.IPAM.Config {
			if cfg.Subnet != "" {
				subnets = append(subnets, cfg.Subnet)
			}
			if cfg.Gateway != "" {
				gateways = append(gateways, cfg.Gateway)
			}
		}

		result = append(result, api.DockerNetwork{
			ID:         n.ID,
			Name:       n.Name,
			Driver:     n.Driver,
			Scope:      n.Scope,
			Subnets:    subnets,
			Gateways:   gateways,
			Containers: containerCounts[n.ID],
			BuiltIn:    isBuiltInNetwork(n.Name),
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result
}

// isBuiltInNetwork reports whether a network ships with Docker itself.
func isBuiltInNetwork(name string) bool {
	switch name {
	case "bridge", "host", "none":
		return true
	default:
		return false
	}
}
