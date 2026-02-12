package engine

import (
	"context"
	"dockgo/api"
	"encoding/json"
	"fmt"
	"io"

	"github.com/docker/docker/api/types/image"
)

// PullEvent represents a single progress update from the Docker daemon
type PullEvent struct {
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
	Progress       string `json:"progress,omitempty"`
	ProgressDetail struct {
		Current int64 `json:"current"`
		Total   int64 `json:"total"`
	} `json:"progressDetail"`
	Id string `json:"id,omitempty"`
}

func (d *DiscoveryEngine) PullImage(ctx context.Context, imageName string, onProgress func(api.PullProgressEvent)) error {
	reader, err := d.Client.ImagePull(ctx, imageName, image.PullOptions{})
	if err != nil {
		return err
	}
	defer reader.Close()

	decoder := json.NewDecoder(reader)
	for {
		var event PullEvent
		if err := decoder.Decode(&event); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		if event.Error != "" {
			return fmt.Errorf("pull error: %s", event.Error)
		}

		if onProgress != nil {
			progEvt := api.PullProgressEvent{
				Type:      "pull_progress",
				Container: imageName,
				Status:    event.Status,
			}

			if event.ProgressDetail.Total > 0 {
				progEvt.Percent = float64(event.ProgressDetail.Current) / float64(event.ProgressDetail.Total) * 100
			}

			onProgress(progEvt)
		}
	}
	return nil
}
