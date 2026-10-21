package engine

import (
	"reflect"
	"testing"

	"dockgo/api"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/volume"
)

func TestSummarizeVolumesIncludesStackAndUsedBy(t *testing.T) {
	volumes := []*volume.Volume{
		{
			Name:       "logs",
			Driver:     "local",
			Scope:      "local",
			Mountpoint: "/var/lib/docker/volumes/logs/_data",
			CreatedAt:  "2024-02-02T00:00:00Z",
			Labels: map[string]string{
				"com.docker.compose.project": "unused-project",
			},
		},
		{
			Name:       "data",
			Driver:     "local",
			Scope:      "local",
			Mountpoint: "/var/lib/docker/volumes/data/_data",
			CreatedAt:  "2024-01-01T00:00:00Z",
		},
		{
			Name:       "scratch",
			Driver:     "local",
			Scope:      "local",
			Mountpoint: "/var/lib/docker/volumes/scratch/_data",
			CreatedAt:  "2024-03-03T00:00:00Z",
			Labels: map[string]string{
				anonymousVolumeLabel: "",
			},
		},
		nil,
	}

	usage := map[string]volumeUsage{
		"data": {
			containers: []string{"app", "db"},
			stacks:     []string{"app"},
		},
	}

	sizes := map[string]int64{
		"data":    2048,
		"scratch": 512,
	}

	got := summarizeVolumes(volumes, usage, sizes)

	want := []api.DockerVolume{
		{
			Name:       "data",
			Driver:     "local",
			Scope:      "local",
			Mountpoint: "/var/lib/docker/volumes/data/_data",
			CreatedAt:  "2024-01-01T00:00:00Z",
			Containers: 2,
			Stacks:     []string{"app"},
			UsedBy:     []string{"app", "db"},
			Size:       2048,
		},
		{
			Name:       "logs",
			Driver:     "local",
			Scope:      "local",
			Mountpoint: "/var/lib/docker/volumes/logs/_data",
			CreatedAt:  "2024-02-02T00:00:00Z",
			Containers: 0,
			Stacks:     []string{"unused-project"},
			UsedBy:     []string{},
			Size:       -1,
		},
		{
			Name:       "scratch",
			Driver:     "local",
			Scope:      "local",
			Mountpoint: "/var/lib/docker/volumes/scratch/_data",
			CreatedAt:  "2024-03-03T00:00:00Z",
			Containers: 0,
			Stacks:     []string{},
			UsedBy:     []string{},
			Anonymous:  true,
			Size:       512,
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("summarizeVolumes() = %#v, want %#v", got, want)
	}
}

func TestSummarizeVolumeDetail(t *testing.T) {
	vol := volume.Volume{
		Name:       "data",
		Driver:     "local",
		Scope:      "local",
		Mountpoint: "/var/lib/docker/volumes/data/_data",
		CreatedAt:  "2024-01-01T00:00:00Z",
		Labels: map[string]string{
			"com.docker.compose.project": "web",
			"com.docker.compose.volume":  "data",
		},
	}

	containers := []container.Summary{
		{
			ID:     "ccc333",
			Names:  []string{"/zeta"},
			Labels: map[string]string{"com.docker.compose.project": "web"},
			Mounts: []container.MountPoint{
				{Type: "volume", Name: "data"},
			},
		},
		{
			ID:    "aaa111",
			Names: []string{"/alpha"},
			Mounts: []container.MountPoint{
				{Type: "volume", Name: "data"},
			},
		},
		{
			ID:    "bbb222",
			Names: []string{"/other"},
			Mounts: []container.MountPoint{
				{Type: "volume", Name: "other"},
			},
		},
	}

	got := summarizeVolumeDetail(vol, containers)

	want := api.DockerVolumeDetail{
		Name:       "data",
		Driver:     "local",
		Scope:      "local",
		Mountpoint: "/var/lib/docker/volumes/data/_data",
		CreatedAt:  "2024-01-01T00:00:00Z",
		Labels:     vol.Labels,
		Stacks:     []string{"web"},
		Containers: []api.DockerVolumeContainer{
			{ID: "aaa111", Name: "alpha"},
			{ID: "ccc333", Name: "zeta"},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("summarizeVolumeDetail() = %#v, want %#v", got, want)
	}
}

func TestCollectVolumeUsage(t *testing.T) {
	containers := []container.Summary{
		{
			Names:  []string{"/app"},
			Labels: map[string]string{"com.docker.compose.project": "web"},
			Mounts: []container.MountPoint{
				{Type: "volume", Name: "data"},
				{Type: "bind", Source: "/host/path"},
			},
		},
		{
			Names:  []string{"/db"},
			Labels: map[string]string{"com.docker.compose.project": "web"},
			Mounts: []container.MountPoint{
				{Type: "volume", Name: "data"},
				{Type: "volume", Name: "logs"},
			},
		},
		{
			Names: []string{"/standalone"},
			Mounts: []container.MountPoint{
				{Type: "volume", Name: "logs"},
			},
		},
	}

	got := collectVolumeUsage(containers)
	want := map[string]volumeUsage{
		"data": {
			containers: []string{"app", "db"},
			stacks:     []string{"web"},
		},
		"logs": {
			containers: []string{"db", "standalone"},
			stacks:     []string{"web"},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("collectVolumeUsage() = %#v, want %#v", got, want)
	}
}

func TestVolumeSizes(t *testing.T) {
	volumes := []*volume.Volume{
		{Name: "data", UsageData: &volume.UsageData{Size: 1024}},
		{Name: "unknown"},
		nil,
	}

	got := volumeSizes(volumes)
	want := map[string]int64{"data": 1024, "unknown": -1}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("volumeSizes() = %#v, want %#v", got, want)
	}
}
