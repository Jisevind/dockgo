package stacks

import "github.com/docker/docker/api/types/filters"

func labelFilter(labels map[string]string) filters.Args {
	args := filters.NewArgs()
	for key, value := range labels {
		if value == "" {
			continue
		}
		args.Add("label", key+"="+value)
	}
	return args
}
