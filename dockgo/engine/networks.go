package engine

import (
	"context"
	"sort"
	"strings"

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
		subnets, gateways := networkIPAM(n.IPAM.Config)

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

// GetNetwork returns the expandable overview for one network.
func (d *DiscoveryEngine) GetNetwork(ctx context.Context, name string) (api.DockerNetworkDetail, error) {
	inspect, err := d.Client.NetworkInspect(ctx, name, network.InspectOptions{})
	if err != nil {
		return api.DockerNetworkDetail{}, err
	}

	containers, err := d.Client.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return api.DockerNetworkDetail{}, err
	}

	return summarizeNetworkDetail(inspect, containers), nil
}

// summarizeNetworkDetail lists the containers attached to a network, including
// each container's Compose project.
func summarizeNetworkDetail(inspect network.Inspect, containers []container.Summary) api.DockerNetworkDetail {
	subnets, gateways := networkIPAM(inspect.IPAM.Config)
	byID := make(map[string]container.Summary, len(containers))
	for _, c := range containers {
		byID[c.ID] = c
	}

	detail := api.DockerNetworkDetail{
		ID:         inspect.ID,
		Name:       inspect.Name,
		Driver:     inspect.Driver,
		Scope:      inspect.Scope,
		Subnets:    subnets,
		Gateways:   gateways,
		BuiltIn:    isBuiltInNetwork(inspect.Name),
		Containers: make([]api.DockerNetworkContainer, 0, len(inspect.Containers)),
		Stacks:     []string{},
	}

	stacks := make(map[string]bool)
	for id, endpoint := range inspect.Containers {
		name := strings.TrimPrefix(endpoint.Name, "/")
		summary := byID[id]
		if name == "" && len(summary.Names) > 0 {
			name = strings.TrimPrefix(summary.Names[0], "/")
		}
		stack := summary.Labels[composeProjectLabel]
		if stack != "" {
			stacks[stack] = true
		}

		detail.Containers = append(detail.Containers, api.DockerNetworkContainer{
			ID:          id,
			Name:        name,
			IPv4Address: stripCIDR(endpoint.IPv4Address),
			IPv6Address: stripCIDR(endpoint.IPv6Address),
			Stack:       stack,
		})
	}
	for stack := range stacks {
		detail.Stacks = append(detail.Stacks, stack)
	}
	sort.Strings(detail.Stacks)
	sort.Slice(detail.Containers, func(i, j int) bool {
		left := strings.ToLower(detail.Containers[i].Name)
		right := strings.ToLower(detail.Containers[j].Name)
		if left != right {
			return left < right
		}
		return detail.Containers[i].ID < detail.Containers[j].ID
	})

	return detail
}

func networkIPAM(configs []network.IPAMConfig) (subnets, gateways []string) {
	subnets = make([]string, 0, len(configs))
	gateways = make([]string, 0, len(configs))
	for _, cfg := range configs {
		if cfg.Subnet != "" {
			subnets = append(subnets, cfg.Subnet)
		}
		if cfg.Gateway != "" {
			gateways = append(gateways, cfg.Gateway)
		}
	}
	return subnets, gateways
}

func stripCIDR(value string) string {
	if value == "" {
		return ""
	}
	return strings.SplitN(value, "/", 2)[0]
}
