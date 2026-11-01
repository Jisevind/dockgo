package server

import (
	"sort"
	"strings"

	"dockgo/api"
	"dockgo/stacks"
)

// buildStackOverviews groups containers under their registered stacks and
// aggregates the live metrics shown on the stacks page.
func buildStackOverviews(stackList []stacks.Stack, containers []api.ContainerOverview) []api.StackOverview {
	managed := make(map[string]string)
	projects := make(map[string][]string)
	for _, stack := range stackList {
		for _, containerID := range stack.ManagedContainers {
			managed[containerID] = stack.ID
		}
		if stack.ProjectName != "" {
			projects[stack.ProjectName] = append(projects[stack.ProjectName], stack.ID)
		}
	}

	members := make(map[string][]api.ContainerOverview)
	presentIDs := make(map[string]bool, len(containers))
	// Containers without a limit report the host total, so the largest limit
	// seen bounds what a stack's summed limit can mean.
	var hostMemory uint64
	for _, container := range containers {
		presentIDs[container.ID] = true
		if container.MemoryLimit > hostMemory {
			hostMemory = container.MemoryLimit
		}
		if stackID, ok := managed[container.ID]; ok {
			members[stackID] = append(members[stackID], container)
			continue
		}
		if container.ComposeProject == "" {
			continue
		}
		for _, stackID := range projects[container.ComposeProject] {
			members[stackID] = append(members[stackID], container)
		}
	}

	result := make([]api.StackOverview, 0, len(stackList))
	for _, stack := range stackList {
		row := api.StackOverview{
			ID:        stack.ID,
			Name:      stack.Name,
			Ownership: stackOwnershipState(stack, presentIDs, members[stack.ID]),
			Source:    stackSourceLabel(stack.Kind),
			Location:  stackLocation(stack),
			Members:   []api.ContainerOverview{},
		}

		stackMembers := members[stack.ID]
		sort.Slice(stackMembers, func(i, j int) bool {
			return strings.ToLower(stackMembers[i].Name) < strings.ToLower(stackMembers[j].Name)
		})

		networks := make(map[string]bool)
		volumes := make(map[string]bool)
		for _, member := range stackMembers {
			row.Containers++
			if member.State == "running" {
				row.Running++
			} else {
				row.Stopped++
			}
			row.CPUPercent += member.CPUPercent
			row.MemoryUsed += member.MemoryUsed
			row.MemoryLimit += member.MemoryLimit
			row.NetRx += member.NetRx
			row.NetTx += member.NetTx
			row.DiskRead += member.DiskRead
			row.DiskWrite += member.DiskWrite
			for _, network := range member.Networks {
				networks[network] = true
			}
			for _, volume := range member.Volumes {
				volumes[volume] = true
			}
		}
		if hostMemory > 0 && row.MemoryLimit > hostMemory {
			row.MemoryLimit = hostMemory
		}
		row.Networks = len(networks)
		row.Volumes = len(volumes)
		row.Members = stackMembers

		switch {
		case row.Running > 0:
			row.Status = "running"
		case row.Containers > 0:
			row.Status = "stopped"
		default:
			row.Status = "unknown"
		}

		result = append(result, row)
	}

	sort.Slice(result, func(i, j int) bool {
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})
	return result
}

func stackOwnershipState(stack stacks.Stack, presentIDs map[string]bool, members []api.ContainerOverview) string {
	if len(stack.ManagedContainers) == 0 {
		return "unbound"
	}

	owned := make(map[string]bool, len(stack.ManagedContainers))
	for _, containerID := range stack.ManagedContainers {
		if !presentIDs[containerID] {
			return "drifted"
		}
		owned[containerID] = true
	}

	for _, member := range members {
		if !owned[member.ID] {
			return "drifted"
		}
	}

	return "bound"
}

func stackSourceLabel(kind stacks.Kind) string {
	switch kind {
	case stacks.KindComposeFile:
		return "Compose file"
	case stacks.KindComposeFiles:
		return "Compose files"
	case stacks.KindGitRepo:
		return "Git repo"
	default:
		return "Unknown"
	}
}

func stackLocation(stack stacks.Stack) string {
	location := strings.TrimSpace(stack.WorkingDir)
	if location == "" {
		return "Not set"
	}
	return location
}
