package api

type ContainerUpdate struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Image           string `json:"image"`
	LocalDigest     string `json:"local_digest"`
	RemoteDigest    string `json:"remote_digest"`
	UpdateAvailable bool   `json:"update_available"`
	// "checked", "updating", "updated", "error"
	Status string            `json:"status"`
	Error  string            `json:"error,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
	Tag    string            `json:"tag,omitempty"`
}

type CheckReport struct {
	Containers []ContainerUpdate `json:"containers"`
}

type ProgressEvent struct {
	Type            string `json:"type"`      // "start", "progress", "done", "error"
	Current         int    `json:"current"`   // Current count
	Total           int    `json:"total"`     // Total count
	Container       string `json:"container"` // Container name being checked
	Status          string `json:"status"`    // result of check
	UpdateAvailable bool   `json:"update_available"`
}

type PullProgressEvent struct {
	Type      string  `json:"type"`              // "pull_progress"
	Container string  `json:"container"`         // Container/Image name
	Status    string  `json:"status"`            // "Downloading", "Extracting", etc.
	Percent   float64 `json:"percent,omitempty"` // 0-100
}
