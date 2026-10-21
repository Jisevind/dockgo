package engine

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"dockgo/api"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
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

// PruneImages removes dangling images, or all unused images when all is true.
func (d *DiscoveryEngine) PruneImages(ctx context.Context, all bool) (api.ImagePruneResult, error) {
	report, err := d.Client.ImagesPrune(ctx, filters.NewArgs(
		filters.Arg("dangling", strconv.FormatBool(!all)),
	))
	if err != nil {
		return api.ImagePruneResult{}, err
	}
	return summarizePruneReport(report), nil
}

func summarizePruneReport(report image.PruneReport) api.ImagePruneResult {
	result := api.ImagePruneResult{SpaceReclaimed: report.SpaceReclaimed}
	for _, deleted := range report.ImagesDeleted {
		if deleted.Deleted != "" {
			result.ImagesDeleted++
		}
	}
	return result
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

// GetImage returns the expandable overview for one image.
func (d *DiscoveryEngine) GetImage(ctx context.Context, id string) (api.DockerImageDetail, error) {
	inspect, err := d.Client.ImageInspect(ctx, id)
	if err != nil {
		return api.DockerImageDetail{}, err
	}

	containers, err := d.Client.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return api.DockerImageDetail{}, err
	}

	return summarizeImageDetail(inspect, containers), nil
}

// summarizeImageDetail lists the containers using an image and the Compose
// projects they belong to.
func summarizeImageDetail(inspect image.InspectResponse, containers []container.Summary) api.DockerImageDetail {
	detail := api.DockerImageDetail{
		ID:         inspect.ID,
		RepoTags:   append([]string{}, inspect.RepoTags...),
		Size:       inspect.Size,
		Containers: []api.DockerImageContainer{},
		Stacks:     []string{},
	}
	if detail.RepoTags == nil {
		detail.RepoTags = []string{}
	}
	if created, err := time.Parse(time.RFC3339Nano, inspect.Created); err == nil {
		detail.Created = created.Unix()
	}

	stacks := make(map[string]bool)
	for _, c := range containers {
		if c.ImageID != inspect.ID {
			continue
		}
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		stack := c.Labels[composeProjectLabel]
		if stack != "" {
			stacks[stack] = true
		}
		detail.Containers = append(detail.Containers, api.DockerImageContainer{
			ID:    c.ID,
			Name:  name,
			State: c.State,
			Stack: stack,
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
