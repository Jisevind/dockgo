package engine

import (
	"context"
	"sort"
	"strings"

	"dockgo/api"
	"dockgo/logger"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/volume"
)

// composeProjectLabel is set by Docker Compose on the volumes and containers it
// creates.
const composeProjectLabel = "com.docker.compose.project"

// anonymousVolumeLabel is set by Docker on volumes created without a name.
const anonymousVolumeLabel = "com.docker.volume.anonymous"

// volumeUsage records which containers use a volume and which Compose projects
// they belong to.
type volumeUsage struct {
	containers []string
	stacks     []string
}

// ListVolumes returns Docker volumes with the containers and stacks using each,
// sorted by name.
func (d *DiscoveryEngine) ListVolumes(ctx context.Context) ([]api.DockerVolume, error) {
	response, err := d.Client.VolumeList(ctx, volume.ListOptions{})
	if err != nil {
		return nil, err
	}

	containers, err := d.Client.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, err
	}

	sizes := d.volumeSizes.get(func(ctx context.Context) (map[string]int64, error) {
		diskUsage, err := d.Client.DiskUsage(ctx, types.DiskUsageOptions{
			Types: []types.DiskUsageObject{types.VolumeObject},
		})
		if err != nil {
			return nil, err
		}
		return volumeSizes(diskUsage.Volumes), nil
	}, func(err error) {
		engineLog.Warn("Failed to determine volume sizes", logger.Any("error", err))
	})
	if sizes == nil {
		sizes = map[string]int64{}
	}

	return summarizeVolumes(response.Volumes, collectVolumeUsage(containers), sizes), nil
}

// volumeSizes maps volume names to their on-disk size. Volumes without usage
// data are reported as -1 so the UI can render them as unknown.
func volumeSizes(volumes []*volume.Volume) map[string]int64 {
	sizes := make(map[string]int64, len(volumes))
	for _, v := range volumes {
		if v == nil {
			continue
		}
		size := int64(-1)
		if v.UsageData != nil {
			size = v.UsageData.Size
		}
		sizes[v.Name] = size
	}
	return sizes
}

// PruneVolumes removes unused anonymous volumes, or all unused volumes when
// all is true.
func (d *DiscoveryEngine) PruneVolumes(ctx context.Context, all bool) (api.VolumePruneResult, error) {
	args := filters.NewArgs()
	if all {
		args.Add("all", "true")
	}

	report, err := d.Client.VolumesPrune(ctx, args)
	if err != nil {
		return api.VolumePruneResult{}, err
	}

	return api.VolumePruneResult{
		VolumesDeleted: len(report.VolumesDeleted),
		SpaceReclaimed: report.SpaceReclaimed,
	}, nil
}

// collectVolumeUsage maps volume names to the containers mounting them and the
// Compose projects those containers belong to.
func collectVolumeUsage(containers []container.Summary) map[string]volumeUsage {
	usage := make(map[string]volumeUsage)
	for _, c := range containers {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		project := c.Labels[composeProjectLabel]

		for _, mount := range c.Mounts {
			if mount.Type != "volume" || mount.Name == "" {
				continue
			}
			u := usage[mount.Name]
			if name != "" && !containsString(u.containers, name) {
				u.containers = append(u.containers, name)
			}
			if project != "" && !containsString(u.stacks, project) {
				u.stacks = append(u.stacks, project)
			}
			usage[mount.Name] = u
		}
	}

	for name, u := range usage {
		sort.Strings(u.containers)
		sort.Strings(u.stacks)
		usage[name] = u
	}
	return usage
}

// GetVolume returns the overview details for one volume.
func (d *DiscoveryEngine) GetVolume(ctx context.Context, name string) (api.DockerVolumeDetail, error) {
	vol, err := d.Client.VolumeInspect(ctx, name)
	if err != nil {
		return api.DockerVolumeDetail{}, err
	}

	containers, err := d.Client.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return api.DockerVolumeDetail{}, err
	}

	return summarizeVolumeDetail(vol, containers), nil
}

// summarizeVolumeDetail builds the volume overview, listing the containers that
// mount the volume and the Compose projects involved.
func summarizeVolumeDetail(vol volume.Volume, containers []container.Summary) api.DockerVolumeDetail {
	detail := api.DockerVolumeDetail{
		Name:       vol.Name,
		Driver:     vol.Driver,
		Scope:      vol.Scope,
		Mountpoint: vol.Mountpoint,
		CreatedAt:  vol.CreatedAt,
		Labels:     vol.Labels,
		Stacks:     []string{},
		Containers: []api.DockerVolumeContainer{},
	}
	if detail.Labels == nil {
		detail.Labels = map[string]string{}
	}

	if project := vol.Labels[composeProjectLabel]; project != "" {
		detail.Stacks = append(detail.Stacks, project)
	}

	for _, c := range containers {
		if !containerUsesVolume(c, vol.Name) {
			continue
		}

		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		detail.Containers = append(detail.Containers, api.DockerVolumeContainer{
			ID:   c.ID,
			Name: name,
		})

		if project := c.Labels[composeProjectLabel]; project != "" &&
			!containsString(detail.Stacks, project) {
			detail.Stacks = append(detail.Stacks, project)
		}
	}

	sort.Slice(detail.Containers, func(i, j int) bool {
		if detail.Containers[i].Name != detail.Containers[j].Name {
			return detail.Containers[i].Name < detail.Containers[j].Name
		}
		return detail.Containers[i].ID < detail.Containers[j].ID
	})
	sort.Strings(detail.Stacks)
	return detail
}

func containerUsesVolume(c container.Summary, name string) bool {
	for _, mount := range c.Mounts {
		if mount.Type == "volume" && mount.Name == name {
			return true
		}
	}
	return false
}

// summarizeVolumes converts Docker volumes into the flat shape the dashboard
// renders, skipping nil entries and sorting by name.
func summarizeVolumes(volumes []*volume.Volume, usage map[string]volumeUsage, sizes map[string]int64) []api.DockerVolume {
	result := make([]api.DockerVolume, 0, len(volumes))
	for _, v := range volumes {
		if v == nil {
			continue
		}

		u := usage[v.Name]
		stacks := append([]string{}, u.stacks...)
		// An unused Compose volume still carries its project label.
		if project := v.Labels[composeProjectLabel]; project != "" &&
			!containsString(stacks, project) {
			stacks = append(stacks, project)
			sort.Strings(stacks)
		}
		if stacks == nil {
			stacks = []string{}
		}
		usedBy := append([]string{}, u.containers...)
		if usedBy == nil {
			usedBy = []string{}
		}
		_, anonymous := v.Labels[anonymousVolumeLabel]
		size, ok := sizes[v.Name]
		if !ok {
			size = -1
		}

		result = append(result, api.DockerVolume{
			Name:       v.Name,
			Driver:     v.Driver,
			Scope:      v.Scope,
			Mountpoint: v.Mountpoint,
			CreatedAt:  v.CreatedAt,
			Containers: len(u.containers),
			Stacks:     stacks,
			UsedBy:     usedBy,
			Anonymous:  anonymous,
			Size:       size,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
