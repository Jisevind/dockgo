package stacks

import "time"

type Kind string

const (
	KindComposeFile  Kind = "compose_file"
	KindComposeFiles Kind = "compose_files"
	KindGitRepo      Kind = "git_repo"
)

type PathMode string

const (
	PathModeHostNative PathMode = "host_native"
	PathModeMapped     PathMode = "mapped"
)

type UpdatePolicy struct {
	Pull          bool `json:"pull"`
	Build         bool `json:"build"`
	DownBeforeUp  bool `json:"down_before_up"`
	ForceRecreate bool `json:"force_recreate"`
	RemoveOrphans bool `json:"remove_orphans"`
}

type HealthPolicy struct {
	UseComposeWait     bool `json:"use_compose_wait"`
	RequireHealthy     bool `json:"require_healthy"`
	WaitTimeoutSeconds int  `json:"wait_timeout_seconds"`
	StartupGrace       int  `json:"startup_grace_seconds"`
}

type DiscoverySelector struct {
	ComposeProject string   `json:"compose_project,omitempty"`
	ServiceNames   []string `json:"service_names,omitempty"`
}

type GitSource struct {
	RepoURL string `json:"repo_url"`
	Ref     string `json:"ref,omitempty"`
	Subdir  string `json:"subdir,omitempty"`
}

type PathMapping struct {
	HostPath      string `json:"host_path"`
	ContainerPath string `json:"container_path"`
}

type Stack struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	ProjectName       string            `json:"project_name"`
	Kind              Kind              `json:"kind"`
	ComposeFiles      []string          `json:"compose_files"`
	EnvFiles          []string          `json:"env_files,omitempty"`
	WorkingDir        string            `json:"working_dir"`
	Profiles          []string          `json:"profiles,omitempty"`
	ProjectEnv        map[string]string `json:"project_env,omitempty"`
	PathMode          PathMode          `json:"path_mode"`
	PathMappings      []PathMapping     `json:"path_mappings,omitempty"`
	UpdatePolicy      UpdatePolicy      `json:"update_policy"`
	HealthPolicy      HealthPolicy      `json:"health_policy"`
	Discovery         DiscoverySelector `json:"discovery_selector,omitempty"`
	GitSource         *GitSource        `json:"git_source,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	ManagedContainers []string          `json:"managed_containers,omitempty"`
	LastDeployStatus  string            `json:"last_deploy_status,omitempty"`
	LastDeployAt      *time.Time        `json:"last_deploy_at,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

type ValidationResult struct {
	Valid    bool     `json:"valid"`
	Issues   []string `json:"issues,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

func DefaultUpdatePolicy() UpdatePolicy {
	return UpdatePolicy{
		Pull:          true,
		Build:         false,
		DownBeforeUp:  false,
		ForceRecreate: false,
		RemoveOrphans: true,
	}
}

func DefaultHealthPolicy() HealthPolicy {
	return HealthPolicy{
		UseComposeWait:     true,
		RequireHealthy:     true,
		WaitTimeoutSeconds: 120,
		StartupGrace:       20,
	}
}
