package api

type ContainerUpdate struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Image           string `json:"image"`
	LocalDigest     string `json:"local_digest"`
	RemoteDigest    string `json:"remote_digest"`
	UpdateAvailable bool   `json:"update_available"`
	Status string            `json:"status"`
	Error  string            `json:"error,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
	Tag    string            `json:"tag,omitempty"`
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
