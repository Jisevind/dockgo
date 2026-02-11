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
