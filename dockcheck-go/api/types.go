package api

type ContainerUpdate struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Image           string `json:"image"`
	LocalDigest     string `json:"local_digest"`
	RemoteDigest    string `json:"remote_digest"`
	UpdateAvailable bool   `json:"update_available"`
	Status          string `json:"status"` // "checked", "updating", "updated", "error"
	Error           string `json:"error,omitempty"`
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
