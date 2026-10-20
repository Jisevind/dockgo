package engine

import (
	"context"
	"sort"
	"strings"

	"dockgo/api"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
)

// ListImages returns local images, one row per repository/tag, with the number
// of containers using each image.
func (d *DiscoveryEngine) ListImages(ctx context.Context) ([]api.DockerImage, error) {
	images, err := d.Client.ImageList(ctx, image.ListOptions{})
	if err != nil {
		return nil, err
	}

	containers, err := d.Client.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, err
	}

	return summarizeImages(images, countContainersByImage(containers)), nil
}

// countContainersByImage maps image IDs to the number of containers using them.
func countContainersByImage(containers []container.Summary) map[string]int {
	counts := make(map[string]int)
	for _, c := range containers {
		if c.ImageID == "" {
			continue
		}
		counts[c.ImageID]++
	}
	return counts
}

// summarizeImages expands multi-tag images into one row per tag and sorts the
// rows by repository then tag.
func summarizeImages(summaries []image.Summary, containerCounts map[string]int) []api.DockerImage {
	result := make([]api.DockerImage, 0, len(summaries))
	for _, img := range summaries {
		tags := img.RepoTags
		if len(tags) == 0 {
			tags = []string{""}
		}
		for _, ref := range tags {
			repository, tag := splitImageRef(ref)
			result = append(result, api.DockerImage{
				ID:         img.ID,
				Repository: repository,
				Tag:        tag,
				Created:    img.Created,
				Size:       img.Size,
				Containers: containerCounts[img.ID],
			})
		}
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Repository != result[j].Repository {
			return result[i].Repository < result[j].Repository
		}
		if result[i].Tag != result[j].Tag {
			return result[i].Tag < result[j].Tag
		}
		return result[i].ID < result[j].ID
	})
	return result
}

// splitImageRef splits "repo[:tag]" without mistaking a registry port for a
// tag separator.
func splitImageRef(ref string) (repository, tag string) {
	if ref == "" {
		return "<none>", "<none>"
	}

	lastColon := strings.LastIndex(ref, ":")
	lastSlash := strings.LastIndex(ref, "/")
	if lastColon > lastSlash {
		return ref[:lastColon], ref[lastColon+1:]
	}
	return ref, "latest"
}
