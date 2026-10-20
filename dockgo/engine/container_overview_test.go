package engine

import (
	"reflect"
	"testing"
	"time"

	"dockgo/api"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
)

func TestBuildContainerOverviewRunning(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	started := now.Add(-2 * time.Hour)

	summary := container.Summary{
		ID:    "abc123",
		Names: []string{"/web"},
		Image: "nginx:latest",
		State: "running",
		Ports: []container.Port{
			{PrivatePort: 80, PublicPort: 8080, Type: "tcp"},
			{PrivatePort: 443, PublicPort: 8443, Type: "tcp"},
			{PrivatePort: 9000, Type: "tcp"},
		},
		Labels: map[string]string{
			"com.docker.compose.project": "web-stack",
		},
	}

	inspect := container.InspectResponse{
		ContainerJSONBase: &container.ContainerJSONBase{
			ID: "abc123",
			State: &container.State{
				Status:    "running",
				StartedAt: started.Format(time.RFC3339Nano),
				Health:    &container.Health{Status: "healthy"},
			},
			RestartCount: 3,
		},
		NetworkSettings: &container.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{
				"bridge": {IPAddress: "172.17.0.2"},
			},
		},
	}

	stats := &container.StatsResponse{
		CPUStats: container.CPUStats{
			CPUUsage:    container.CPUUsage{TotalUsage: 1_500_000_000},
			SystemUsage: 4_000_000_000,
			OnlineCPUs:  1,
		},
		PreCPUStats: container.CPUStats{
			CPUUsage:    container.CPUUsage{TotalUsage: 1_000_000_000},
			SystemUsage: 2_000_000_000,
		},
		MemoryStats: container.MemoryStats{
			Usage: 1000,
			Limit: 2000,
			Stats: map[string]uint64{"cache": 200},
		},
		Networks: map[string]container.NetworkStats{
			"eth0": {RxBytes: 100, TxBytes: 200},
			"eth1": {RxBytes: 50, TxBytes: 25},
		},
		BlkioStats: container.BlkioStats{
			IoServiceBytesRecursive: []container.BlkioStatEntry{
				{Op: "read", Value: 10},
				{Op: "read", Value: 5},
				{Op: "write", Value: 20},
			},
		},
	}

	got := buildContainerOverview(summary, inspect, stats, now)

	want := api.ContainerOverview{
		ID:             "abc123",
		Name:           "web",
		Image:          "nginx:latest",
		State:          "running",
		Health:         "healthy",
		UptimeSeconds:  7200,
		RestartCount:   3,
		CPUPercent:     25,
		MemoryUsed:     800,
		MemoryLimit:    2000,
		NetRx:          150,
		NetTx:          225,
		DiskRead:       15,
		DiskWrite:      20,
		IP:             "172.17.0.2",
		Ports:          []string{"8080:80", "8443:443", "9000"},
		ComposeProject: "web-stack",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildContainerOverview() = %#v, want %#v", got, want)
	}
}

func TestBuildContainerOverviewExited(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	finished := now.Add(-90 * time.Minute)

	summary := container.Summary{
		ID:    "def456",
		Names: []string{"/old-job"},
		Image: "busybox:latest",
		State: "exited",
	}
	inspect := container.InspectResponse{
		ContainerJSONBase: &container.ContainerJSONBase{
			ID: "def456",
			State: &container.State{
				Status:     "exited",
				FinishedAt: finished.Format(time.RFC3339Nano),
			},
			RestartCount: 1,
		},
	}

	got := buildContainerOverview(summary, inspect, nil, now)

	if got.UptimeSeconds != 5400 || !got.UptimeAgo {
		t.Fatalf("uptime = %d ago=%v, want 5400 ago=true", got.UptimeSeconds, got.UptimeAgo)
	}
	if got.Health != "" {
		t.Errorf("Health = %q, want empty", got.Health)
	}
	if got.CPUPercent != 0 || got.MemoryUsed != 0 || got.NetRx != 0 || got.DiskRead != 0 {
		t.Errorf("stats should be zero for exited container: %#v", got)
	}
	if got.Ports == nil {
		t.Error("Ports = nil, want empty slice")
	}
}

func TestSortContainerOverviewsByName(t *testing.T) {
	overviews := []api.ContainerOverview{
		{Name: "zeta"},
		{Name: "alpha"},
		{Name: "Beta"},
	}
	sortContainerOverviews(overviews)

	got := []string{overviews[0].Name, overviews[1].Name, overviews[2].Name}
	want := []string{"alpha", "Beta", "zeta"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sorted names = %v, want %v", got, want)
	}
}
