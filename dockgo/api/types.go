package api

// DockerNetwork is the dashboard-facing summary of a Docker network.
type DockerNetwork struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Driver     string   `json:"driver"`
	Scope      string   `json:"scope"`
	Subnets    []string `json:"subnets"`
	Gateways   []string `json:"gateways"`
	Containers int      `json:"containers"`
	BuiltIn    bool     `json:"built_in"`
}

// DockerNetworkContainer identifies a container attached to a network.
type DockerNetworkContainer struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	IPv4Address string `json:"ipv4_address"`
	IPv6Address string `json:"ipv6_address"`
	Stack       string `json:"stack"`
}

// DockerNetworkDetail is the expandable overview for one network.
type DockerNetworkDetail struct {
	ID         string                   `json:"id"`
	Name       string                   `json:"name"`
	Driver     string                   `json:"driver"`
	Scope      string                   `json:"scope"`
	Subnets    []string                 `json:"subnets"`
	Gateways   []string                 `json:"gateways"`
	BuiltIn    bool                     `json:"built_in"`
	Containers []DockerNetworkContainer `json:"containers"`
	Stacks     []string                 `json:"stacks"`
}

// DockerImage is one repository/tag row on the images page.
type DockerImage struct {
	ID         string `json:"id"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Created    int64  `json:"created"`
	Size       int64  `json:"size"`
	Containers int    `json:"containers"`
}

// ImagePruneResult summarizes a Docker image prune operation.
type ImagePruneResult struct {
	ImagesDeleted  int    `json:"images_deleted"`
	SpaceReclaimed uint64 `json:"space_reclaimed"`
}

// DockerImageContainer identifies a container using an image.
type DockerImageContainer struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
	Stack string `json:"stack"`
}

// DockerImageDetail is the expandable overview for one image.
type DockerImageDetail struct {
	ID         string                 `json:"id"`
	RepoTags   []string               `json:"repo_tags"`
	Created    int64                  `json:"created"`
	Size       int64                  `json:"size"`
	Containers []DockerImageContainer `json:"containers"`
	Stacks     []string               `json:"stacks"`
}

// DockerVolume is the dashboard-facing summary of a Docker volume.
type DockerVolume struct {
	Name       string   `json:"name"`
	Driver     string   `json:"driver"`
	Scope      string   `json:"scope"`
	Mountpoint string   `json:"mountpoint"`
	CreatedAt  string   `json:"created_at"`
	Containers int      `json:"containers"`
	Stacks     []string `json:"stacks"`
	UsedBy     []string `json:"used_by"`
	Anonymous  bool     `json:"anonymous"`
	Size       int64    `json:"size"`
}

// VolumePruneResult summarizes a Docker volume prune operation.
type VolumePruneResult struct {
	VolumesDeleted int    `json:"volumes_deleted"`
	SpaceReclaimed uint64 `json:"space_reclaimed"`
}

// DockerVolumeContainer identifies a container that mounts a volume.
type DockerVolumeContainer struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// DockerVolumeDetail is the overview payload for one volume.
type DockerVolumeDetail struct {
	Name       string                  `json:"name"`
	Driver     string                  `json:"driver"`
	Scope      string                  `json:"scope"`
	Mountpoint string                  `json:"mountpoint"`
	CreatedAt  string                  `json:"created_at"`
	Labels     map[string]string       `json:"labels"`
	Stacks     []string                `json:"stacks"`
	Containers []DockerVolumeContainer `json:"containers"`
}

// ContainerOverview is one row on the containers page.
type ContainerOverview struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Image          string   `json:"image"`
	State          string   `json:"state"`
	Health         string   `json:"health"`
	UptimeSeconds  int64    `json:"uptime_seconds"`
	UptimeAgo      bool     `json:"uptime_ago"`
	RestartCount   int      `json:"restart_count"`
	CPUPercent     float64  `json:"cpu_percent"`
	MemoryUsed     uint64   `json:"memory_used"`
	MemoryLimit    uint64   `json:"memory_limit"`
	NetRx          uint64   `json:"net_rx"`
	NetTx          uint64   `json:"net_tx"`
	DiskRead       uint64   `json:"disk_read"`
	DiskWrite      uint64   `json:"disk_write"`
	IP             string   `json:"ip"`
	Ports          []string `json:"ports"`
	ComposeProject string   `json:"compose_project"`
	Networks       []string `json:"networks"`
	Volumes        []string `json:"volumes"`
}

// StackOverview is one row on the stacks page, aggregating its containers.
type StackOverview struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Status      string              `json:"status"`
	Ownership   string              `json:"ownership"`
	Source      string              `json:"source"`
	Location    string              `json:"location"`
	Containers  int                 `json:"containers"`
	Running     int                 `json:"running"`
	Stopped     int                 `json:"stopped"`
	CPUPercent  float64             `json:"cpu_percent"`
	MemoryUsed  uint64              `json:"memory_used"`
	MemoryLimit uint64              `json:"memory_limit"`
	NetRx       uint64              `json:"net_rx"`
	NetTx       uint64              `json:"net_tx"`
	DiskRead    uint64              `json:"disk_read"`
	DiskWrite   uint64              `json:"disk_write"`
	Networks    int                 `json:"networks"`
	Volumes     int                 `json:"volumes"`
	Members     []ContainerOverview `json:"members"`
}

type ContainerUpdate struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Image           string            `json:"image"`
	LocalDigest     string            `json:"local_digest"`
	RemoteDigest    string            `json:"remote_digest"`
	UpdateAvailable bool              `json:"update_available"`
	Status          string            `json:"status"`
	Error           string            `json:"error,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Tag             string            `json:"tag,omitempty"`
}

type CheckReport struct {
	Containers []ContainerUpdate `json:"containers"`
}

type ProgressEvent struct {
	Type            string  `json:"type"`
	Current         int     `json:"current"`
	Total           int     `json:"total"`
	Container       string  `json:"container"`
	Status          string  `json:"status"`
	Error           string  `json:"error,omitempty"`
	UpdateAvailable bool    `json:"update_available"`
	Percent         float64 `json:"percent,omitempty"`
}

type PullProgressEvent struct {
	Type      string  `json:"type"`
	Container string  `json:"container"`
	Status    string  `json:"status"`
	Percent   float64 `json:"percent,omitempty"`
}
