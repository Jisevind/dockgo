package engine

import (
	"reflect"
	"testing"

	"dockgo/api"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
)

func TestSummarizeNetworksMapsAndSorts(t *testing.T) {
	summaries := []network.Summary{
		{
			ID:     "id-web",
			Name:   "web_default",
			Driver: "bridge",
			Scope:  "local",
			IPAM: network.IPAM{
				Config: []network.IPAMConfig{
					{Subnet: "172.20.0.0/16", Gateway: "172.20.0.1"},
				},
			},
			Containers: map[string]network.EndpointResource{
				"c1": {},
				"c2": {},
			},
		},
		{
			ID:     "id-bridge",
			Name:   "bridge",
			Driver: "bridge",
			Scope:  "local",
			IPAM: network.IPAM{
				Config: []network.IPAMConfig{
					{Subnet: "172.17.0.0/16", Gateway: "172.17.0.1"},
				},
			},
		},
		{
			ID:     "id-host",
			Name:   "host",
			Driver: "host",
			Scope:  "local",
		},
	}

	got := summarizeNetworks(summaries, map[string]int{
		"id-bridge": 1,
		"id-web":    2,
	})

	want := []api.DockerNetwork{
		{
			ID:         "id-bridge",
			Name:       "bridge",
			Driver:     "bridge",
			Scope:      "local",
			Subnets:    []string{"172.17.0.0/16"},
			Gateways:   []string{"172.17.0.1"},
			Containers: 1,
			BuiltIn:    true,
		},
		{
			ID:         "id-host",
			Name:       "host",
			Driver:     "host",
			Scope:      "local",
			Subnets:    []string{},
			Gateways:   []string{},
			Containers: 0,
			BuiltIn:    true,
		},
		{
			ID:         "id-web",
			Name:       "web_default",
			Driver:     "bridge",
			Scope:      "local",
			Subnets:    []string{"172.20.0.0/16"},
			Gateways:   []string{"172.20.0.1"},
			Containers: 2,
			BuiltIn:    false,
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("summarizeNetworks() = %#v, want %#v", got, want)
	}
}

func TestCountContainersByNetwork(t *testing.T) {
	containers := []container.Summary{
		{
			NetworkSettings: &container.NetworkSettingsSummary{
				Networks: map[string]*network.EndpointSettings{
					"web_default": {NetworkID: "id-web"},
				},
			},
		},
		{
			NetworkSettings: &container.NetworkSettingsSummary{
				Networks: map[string]*network.EndpointSettings{
					"web_default": {NetworkID: "id-web"},
					"bridge":      {NetworkID: "id-bridge"},
				},
			},
		},
		{
			// Containers without network settings (e.g. host network mode)
			// must not panic or be counted.
			NetworkSettings: nil,
		},
	}

	got := countContainersByNetwork(containers)
	want := map[string]int{"id-web": 2, "id-bridge": 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("countContainersByNetwork() = %v, want %v", got, want)
	}
}

func TestSummarizeNetworksKeepsMultipleSubnets(t *testing.T) {
	got := summarizeNetworks([]network.Summary{
		{
			Name:   "dual",
			Driver: "bridge",
			Scope:  "local",
			IPAM: network.IPAM{
				Config: []network.IPAMConfig{
					{Subnet: "172.30.0.0/16", Gateway: "172.30.0.1"},
					{Subnet: "fd00:30::/64", Gateway: "fd00:30::1"},
				},
			},
		},
	}, nil)

	if len(got) != 1 {
		t.Fatalf("summarizeNetworks() returned %d networks, want 1", len(got))
	}
	if want := []string{"172.30.0.0/16", "fd00:30::/64"}; !reflect.DeepEqual(got[0].Subnets, want) {
		t.Errorf("Subnets = %v, want %v", got[0].Subnets, want)
	}
	if want := []string{"172.30.0.1", "fd00:30::1"}; !reflect.DeepEqual(got[0].Gateways, want) {
		t.Errorf("Gateways = %v, want %v", got[0].Gateways, want)
	}
}

func TestSummarizeNetworkDetail(t *testing.T) {
	inspect := network.Inspect{
		ID:     "id-web",
		Name:   "web_default",
		Driver: "bridge",
		Scope:  "local",
		IPAM: network.IPAM{
			Config: []network.IPAMConfig{
				{Subnet: "172.20.0.0/16", Gateway: "172.20.0.1"},
			},
		},
		Containers: map[string]network.EndpointResource{
			"c1": {
				Name:        "web-app",
				IPv4Address: "172.20.0.2/16",
			},
			"c2": {
				Name:        "db",
				IPv4Address: "172.20.0.3/16",
				IPv6Address: "fd00::3/64",
			},
			"c3": {
				Name:        "external",
				IPv4Address: "172.20.0.4/16",
			},
		},
	}

	containers := []container.Summary{
		{
			ID:     "c1",
			Names:  []string{"/web-app"},
			Labels: map[string]string{"com.docker.compose.project": "web"},
		},
		{
			ID:    "c2",
			Names: []string{"/db"},
		},
	}

	got := summarizeNetworkDetail(inspect, containers)

	want := api.DockerNetworkDetail{
		ID:       "id-web",
		Name:     "web_default",
		Driver:   "bridge",
		Scope:    "local",
		Subnets:  []string{"172.20.0.0/16"},
		Gateways: []string{"172.20.0.1"},
		BuiltIn:  false,
		Containers: []api.DockerNetworkContainer{
			{ID: "c2", Name: "db", IPv4Address: "172.20.0.3", IPv6Address: "fd00::3"},
			{ID: "c3", Name: "external", IPv4Address: "172.20.0.4"},
			{ID: "c1", Name: "web-app", IPv4Address: "172.20.0.2", Stack: "web"},
		},
		Stacks: []string{"web"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("summarizeNetworkDetail() = %#v, want %#v", got, want)
	}
}
