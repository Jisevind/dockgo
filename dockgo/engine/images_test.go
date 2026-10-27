package engine

import (
	"reflect"
	"testing"
	"time"

	"dockgo/api"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
)

func TestSummarizeImagesExpandsTagsAndCountsContainers(t *testing.T) {
	summaries := []image.Summary{
		{
			ID:       "sha256:aaa",
			RepoTags: []string{"nginx:latest"},
			Created:  100,
			Size:     1000,
		},
		{
			ID:       "sha256:bbb",
			RepoTags: nil,
			Created:  200,
			Size:     2000,
		},
		{
			ID:       "sha256:ccc",
			RepoTags: []string{"registry:5000/app:v1", "app:v2"},
			Created:  300,
			Size:     3000,
		},
	}

	got := summarizeImages(summaries, map[string]int{
		"sha256:aaa": 2,
		"sha256:ccc": 1,
	})

	want := []api.DockerImage{
		{ID: "sha256:bbb", Repository: "<none>", Tag: "<none>", Created: 200, Size: 2000, Containers: 0},
		{ID: "sha256:ccc", Repository: "app", Tag: "v2", Created: 300, Size: 3000, Containers: 1},
		{ID: "sha256:aaa", Repository: "nginx", Tag: "latest", Created: 100, Size: 1000, Containers: 2},
		{ID: "sha256:ccc", Repository: "registry:5000/app", Tag: "v1", Created: 300, Size: 3000, Containers: 1},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("summarizeImages() = %#v, want %#v", got, want)
	}
}

func TestSplitImageRef(t *testing.T) {
	cases := []struct {
		ref        string
		repository string
		tag        string
	}{
		{"nginx", "nginx", "latest"},
		{"nginx:1.27", "nginx", "1.27"},
		{"registry:5000/app", "registry:5000/app", "latest"},
		{"registry:5000/app:v1", "registry:5000/app", "v1"},
		{"", "<none>", "<none>"},
	}
	for _, tc := range cases {
		repository, tag := splitImageRef(tc.ref)
		if repository != tc.repository || tag != tc.tag {
			t.Errorf("splitImageRef(%q) = (%q, %q), want (%q, %q)",
				tc.ref, repository, tag, tc.repository, tc.tag)
		}
	}
}

func TestCountContainersByImage(t *testing.T) {
	containers := []container.Summary{
		{ImageID: "sha256:aaa"},
		{ImageID: "sha256:aaa"},
		{ImageID: "sha256:bbb"},
		{ImageID: ""},
	}

	got := countContainersByImage(containers)
	want := map[string]int{"sha256:aaa": 2, "sha256:bbb": 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("countContainersByImage() = %v, want %v", got, want)
	}
}

func TestSummarizeImageDetail(t *testing.T) {
	inspect := image.InspectResponse{
		ID:       "sha256:aaa",
		RepoTags: []string{"nginx:latest"},
		Created:  "2026-10-20T12:00:00Z",
		Size:     1000,
	}
	containers := []container.Summary{
		{
			ID:      "c1",
			Names:   []string{"/web"},
			ImageID: "sha256:aaa",
			State:   "running",
			Labels:  map[string]string{"com.docker.compose.project": "web"},
		},
		{
			ID:      "c2",
			Names:   []string{"/worker"},
			ImageID: "sha256:aaa",
			State:   "exited",
			Labels:  map[string]string{"com.docker.compose.project": "web"},
		},
		{
			ID:      "c3",
			Names:   []string{"/other"},
			ImageID: "sha256:bbb",
			State:   "running",
		},
	}

	got := summarizeImageDetail(inspect, containers)

	want := api.DockerImageDetail{
		ID:       "sha256:aaa",
		RepoTags: []string{"nginx:latest"},
		Created:  time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC).Unix(),
		Size:     1000,
		Containers: []api.DockerImageContainer{
			{ID: "c1", Name: "web", State: "running", Stack: "web"},
			{ID: "c2", Name: "worker", State: "exited", Stack: "web"},
		},
		Stacks: []string{"web"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("summarizeImageDetail() = %#v, want %#v", got, want)
	}
}

func TestSummarizePruneReportCountsDeletedImagesOnly(t *testing.T) {
	report := image.PruneReport{
		ImagesDeleted: []image.DeleteResponse{
			{Deleted: "sha256:aaa"},
			{Untagged: "nginx:latest"},
			{Deleted: "sha256:bbb"},
		},
		SpaceReclaimed: 4096,
	}

	got := summarizePruneReport(report)
	want := api.ImagePruneResult{ImagesDeleted: 2, SpaceReclaimed: 4096}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("summarizePruneReport() = %#v, want %#v", got, want)
	}
}
